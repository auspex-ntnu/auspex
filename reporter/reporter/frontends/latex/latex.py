import asyncio
import contextlib
from datetime import datetime
from pathlib import Path
from typing import Any, ContextManager, Final, Type, Union, cast
from auspex_core.models.cve import CVESeverity

from auspex_core.models.scan import ReportData
from loguru import logger
from pylatex import (
    Command,
    Document,
    Figure,
    Foot,
    Head,
    LargeText,
    LineBreak,
    LongTable,
    LongTabularx,
    MediumText,
    MiniPage,
    MultiColumn,
    PageStyle,
    Section,
    Subsection,
    Tabular,
    simple_page_number,
    NewPage,
    Table,
    LongTabu,
    Package,
    Itemize,
)
from pylatex.utils import NoEscape, bold, italic
from ...types.protocols import ScanType
from ...backends.aggregate import AggregateReport
from sanitize_filename import sanitize

from ...types import ScanType, ScanType
from ..shared.plots import (
    piechart_severity,
    scatter_mean_trend,
    scatter_vulnerability_age,
)
from ..shared.tables import (
    cvss_intervals,
    exploitable_vulns,
    image_info,
    severity_vulns_table,
    statistics_table,
    top_vulns_table,
)
from ..shared.models import TableData, PlotData
from .table import init_longtable, add_row
from .utils import hyperlink

# TODO: support aggregate scans

# NOTE ON MUTEX LOCK:
# We create a mutex here to avoid race conditions that can occur when using
# both (Py)Latex and Matplotlib.
#
# We discovered that figures would be mangled if trying to create multiple documents
# in parallel when calling plt.clf(), which is not a threadsafe function.
# We removed the offending plt.clf() calls (they were redundant), however
# it still proves that the issue exists, and future additions to the code could easily
# make it resurface if a developer uses a non-threadsafe Matplotlib function.
#
# For that reason, we keep the mutex in, as it is safer, and latency is not a huge issue.
lock = asyncio.Lock()


async def create_document(
    scan: ScanType, prev_scans: list[ReportData]
) -> "LatexDocument":
    loop = asyncio.get_event_loop()
    # NOTE: it is safer to use a mutex here, because running Matplotlib
    # and pylatex in parallel can cause issues.
    # Calling certain plt.<function> will _very likely_ affect other threads.
    #
    # We could of course make the entire function blocking (replace function body with _do_create_document),
    # but that makes its design inconsistent with the rest of the application code (async).
    async with lock:
        return await loop.run_in_executor(None, _do_create_document, scan, prev_scans)


def _do_create_document(
    scan: ScanType, prev_scans: list[ReportData]
) -> "LatexDocument":
    """NOTE: blocking"""
    d = LatexDocument(scan, prev_scans)
    d.generate_pdf()
    return d


SectionContext = ContextManager[Any]


ROWHEIGHT_SINGLEROW: Final[float] = 1.5
ROWHEIGHT_MULTIROW: Final[float] = 1.0


class LatexDocument:
    filename: str
    plots: list[Path]
    doc: Document
    scan: ScanType
    prev_scans: list[ReportData]

    def __init__(self, scan: ScanType, prev_scans: list[ReportData]) -> None:
        # NOTE: Very important to not have spaces in the filename
        # otherwise the PDF will not be generated.
        # PyLatex (or LaTeX itself) does not handle it well.
        # TODO: make self.filename a Path and check if we can write to it?
        self.directory = "/tmp"  # TODO: use tempfile.gettempdir() or tempfile.mkdtemp()
        self.filename = f"{self.directory}/{sanitize(scan.id)}".replace(" ", "_")
        self.doc = self._init_document()  # type: Document
        self.scan = scan
        self.prev_scans = prev_scans
        self.plots = []

    @property
    def path(self) -> Path:
        # TODO: support alternative file paths?
        return Path(f"{self.doc.default_filepath}.pdf")

    def _init_document(self) -> Document:
        geometry_options = {
            # "landscape": False,
            "margin": "2.54cm",
            # "headheight": "20pt",
            # "headsep": "10pt",
            "includeheadfoot": True,
        }
        return Document(
            self.filename,
            page_numbers=True,
            geometry_options=geometry_options,
        )

    def generate_pdf(self) -> Document:
        """Sets up a document, adds content, and generates a PDF."""
        content_methods = {
            "CVSS Intervals": self.add_table_cvss_intervals,
            "Image Info": self.add_table_image_info,
            "Statistics": self.add_table_statistics,
            "Mean Trend Plot": self.add_plot_mean_trend,
            "Top Vulnerabilities Table": self.add_table_top_vuln,
            "Top Upgradable Vulnerabilities Table": self.add_table_top_vuln_upgradable,
            "Severity Distribution Pie Chart": self.add_plot_severity_piechart,
            "Vulnerability vs Age Scatter Plot": self.add_plot_scatter_vuln_age,
            "Exploitable Vulnerabilities Table": self.add_table_exploitable_vulns,
            "Exploitable Vulnerabilities Pie Chart": self.add_plot_severity_piechart_exploitable,
            "All Critical Vulnerabilities Table": self.add_table_all_critical,
        }
        # List of failed sections
        failed = []  # type: list[str]
        try:
            self.add_packages()
            # self.add_preamble()
            self.add_header()

            for section_name, method in content_methods.items():
                try:
                    # TODO: we could try to modify a COPY of the document
                    # and only overwrite the original document if this method succeeds.
                    method()
                except Exception as e:
                    logger.exception(e)
                    logger.error(f"Failed to create {section_name}")
                    failed.append(section_name)

            self.add_section_failed(failed)
            self.doc.generate_pdf(compiler_args=["-f"])
            logger.debug(f"Generated PDF: {self.path}")
        finally:
            # NOTE: we could implement __enter__ and __exit__ to ensure
            # ALL temporary files are cleaned up (including generated pdf)
            self.delete_temp_files()

    def add_section_failed(self, failed: list[str]) -> None:
        if failed:
            self.doc.append(NewPage())
            with self.doc.create(
                Section("Sections That Failed to Render", numbering=False)
            ):
                with self.doc.create(Itemize()) as itemize:
                    for section_name in failed:
                        itemize.add_item((NoEscape(f"{section_name}")))

    def delete_temp_files(self) -> None:
        """Deletes all temporary files after generating document."""
        # Depending on how (non-)ephemeral these containers are, we could risk
        # using all of the container's memory by carelessly writing to the in-memory filesystem.
        # As a precautionary measure, we make sure all temporary files are cleaned up.
        for plot in self.plots:
            Path(plot).unlink(missing_ok=True)

    def add_packages(self) -> None:
        self.doc.packages.append(Package("hyperref"))

    def add_preamble(self) -> None:
        self.doc.preamble.append(Command("title", self.scan.title))
        self.doc.preamble.append(Command("author", "Auspex"))
        self.doc.preamble.append(Command("date", NoEscape(r"\today")))
        self.doc.append(NoEscape(r"\maketitle"))

    def add_header(self):
        # Add document header
        header = PageStyle("header")

        # Header
        # Create left header
        with header.create(Head("L")):
            # Today's date (ISO format)
            header.append(datetime.now().strftime("%Y-%m-%d"))
        # Create center header
        with header.create(Head("C")):
            header.append(self.scan.title)
        # Create right header
        # with header.create(Head("R")):
        #     header.append("Auspex")

        # Footer

        # Create left footer
        # with header.create(Foot("L")):
        #     header.append("Left Footer")
        # Create center footer
        with header.create(Foot("C")):
            header.append(simple_page_number())

        # Create right footer
        # with header.create(Foot("R")):
        #     header.append("Right Footer")

        self.doc.preamble.append(header)
        self.doc.change_document_style("header")

    def add_table_cvss_intervals(self) -> None:
        tabledata = cvss_intervals()
        self._add_section_longtable(
            tabledata, numbering=False, newpage=False, row_height=ROWHEIGHT_SINGLEROW
        )
        self.doc.append(NoEscape(r"\noindent\rule{\textwidth}{1pt}"))

    def add_table_image_info(self) -> None:
        tabledata = image_info(self.scan)
        self._add_section_longtable(
            tabledata, newpage=False, row_height=ROWHEIGHT_SINGLEROW
        )

    def add_table_statistics(self) -> None:
        """Adds a table with statistics about the scanned image(s)."""
        # TODO: rewrite using _add_section_longtable
        tabledata = statistics_table(self.scan)
        self._add_section_longtable(tabledata, newpage=False)

    def add_table_top_vuln(self) -> None:
        """Adds a table with the top N vulnerabilities."""
        tabledata = top_vulns_table(self.scan, upgradable=False, maxrows=5)
        if not tabledata.rows:
            logger.info(f"No vulnerabilities to report for report {self.scan.id}")
            return
        self._add_section_longtable(tabledata)

    def add_table_top_vuln_upgradable(self) -> None:
        """Adds a table with the top N upgradable vulnerabilities."""
        tabledata = top_vulns_table(self.scan, upgradable=True, maxrows=5)
        if not tabledata.rows:
            logger.info(f"No vulnerabilities to report for report {self.scan.id}")
            return
        self._add_section_longtable(tabledata, newpage=False)

    def add_table_all_critical(self) -> None:
        """Adds a table with all critical vulnerabilities."""
        tabledata = severity_vulns_table(self.scan, severity=CVESeverity.CRITICAL)
        if not tabledata.rows:
            logger.info(f"No vulnerabilities to report for report {self.scan.id}")
            return
        self._add_section_longtable(tabledata)

    def add_plot_mean_trend(self) -> None:
        """Attempts to add a mean CVSSv3 score trend plot to the document."""
        plotdata = scatter_mean_trend(self.scan, self.prev_scans)
        self._add_section_plot(plotdata)

    def add_plot_severity_piechart(self) -> None:
        """Adds pie chart of CVSS severity distribution."""
        plot = piechart_severity(self.scan, self.filename)
        self._add_section_plot(plot)

    def add_plot_severity_piechart_exploitable(self) -> None:
        plot_exploitable = piechart_severity(self.scan, self.filename, exploitable=True)
        self._add_section_plot(plot_exploitable)

    def add_plot_scatter_vuln_age(self) -> None:
        """Adds a scatter plot of vulnerability age vs. CVSSv3 score."""
        plot = scatter_vulnerability_age(self.scan, self.filename)
        self._add_section_plot(plot)

    def add_table_exploitable_vulns(self) -> None:
        """Adds a table of exploitable vulnerabilities."""
        tabledata = exploitable_vulns(self.scan)
        self._add_section_longtable(tabledata)
        # if tabledata.rows:
        #     self._add_section_longtable(tabledata)
        # else:
        #     with self.doc.create(Section(title=tabledata.title)):
        #         self.doc.append("No exploitable vulnerabilities found.")

    def _add_section_longtable(
        self,
        tabledata: TableData,
        numbering: bool = True,
        newpage: bool = True,
        **kwargs,
    ) -> Section:
        """Adds a section with a longtable of the given table data.

        Parameters
        ----------
        tabledata : `TableData`
            Table data to add
        numbering : `bool`, optional
            Whether to number section, by default `True`
        **kwargs
            Additional keyword arguments to pass to `_add_longtable`
        """
        if newpage and not tabledata.empty:  # only make new page if we have rows
            self.doc.append(NewPage())
        with self.doc.create(
            Section(tabledata.title, numbering=numbering)
        ) as section:  # type: Section
            if tabledata.description:
                section.append(tabledata.description)
            section = cast(Section, section)  # mypy
            # Only add table if we have rows
            if not tabledata.empty:
                self._add_longtable(tabledata, LongTabularx, **kwargs)
        return section

    def _add_longtable(
        self,
        tabledata: TableData,
        table_type: Type[LongTable] = LongTabularx,
        row_height: float = ROWHEIGHT_MULTIROW,
        booktabs: bool = True,
    ) -> None:
        """Creates a LongTable wrapped in a Table environment.

        Wrapping it in a table allows us to add captions + more.

        Parameters
        ----------
        tabledata : `TableData`
            Table data to add
        table_type : `Type[LongTable]`
            Type of table to create. This can be any of the LongTable types.
        """
        # Wrap tabular in a table so we can add a caption
        if tabledata.caption:
            ctx = self.doc.create(Table(position="h"))
        else:
            # NOTE:
            # We use a null context when no caption is needed
            # The reason we have to do this, is that longtabularx
            # breaks when attempting to wrap it in a Table.
            # Developers can still use whatever Tabular environment they want,
            # but we can't add a caption to tables that span multiple pages.
            # This is something developers should be aware of when using this method.
            ctx = contextlib.nullcontext()

        with ctx as table:
            # Create the tabular environment
            table_spec = " ".join(["l"] * len(tabledata.header))
            with self.doc.create(
                table_type(table_spec, row_height=row_height, booktabs=booktabs)
            ) as tabular:
                tabular = cast(LongTable, tabular)  # mypy

                init_longtable(tabular, tabledata.header)
                for row in tabledata.rows:
                    add_row(tabular, row)

            # Add caption to table if it exists
            if tabledata.caption:
                table = cast(Table, table)  # mypy
                table.add_caption(tabledata.caption)

    def _add_section_plot(
        self, plotdata: PlotData, numbering: bool = True, newpage: bool = True, **kwargs
    ) -> Section:
        """Adds a section with a plot.

        Parameters
        ----------
        plotdata : `PlotData`
            Plot data to add
        numbering : `bool`, optional
            Whether to number section, by default `True`
        newpage : `bool`, optional
            Whether to start a new page, by default `True`
        """
        if newpage and plotdata.path:
            self.doc.append(NewPage())
        with self.doc.create(
            Section(plotdata.title, numbering=numbering)
        ) as section:  # type: Section
            if plotdata.description:
                section.append(plotdata.description)
            section = cast(Section, section)  # mypy
            self._add_plot(plotdata, **kwargs)
        return section

    def _add_plot(
        self, plotdata: PlotData, width: float = 1.0, position: str = "h"
    ) -> None:
        """Adds a plot to the document."""
        if plotdata.path is not None:
            self.plots.append(plotdata.path)
            with self.doc.create(Figure(position=position)) as fig:
                fig = cast(Figure, fig)  # mypy
                fig.add_image(
                    str(plotdata.path), width=NoEscape(f"{width}" + r"\textwidth")
                )
                fig.add_caption(plotdata.caption)
