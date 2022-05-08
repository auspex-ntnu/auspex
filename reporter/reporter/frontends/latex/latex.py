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
from ..shared.models import TableData
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
        """Fills the document with content and generates a PDF."""
        try:
            self.add_packages()
            self.add_preamble()
            self.add_header()
            self.add_table_cvss_intervals()
            self.add_table_image_info()
            self.add_table_statistics()
            self.add_plot_mean_trend()
            self.add_table_top_vuln()
            self.add_table_top_vuln_upgradable()
            self.add_plot_severity_piechart()
            self.add_plot_scatter_vuln_age()
            self.add_table_exploitable_vulns()
            self.add_table_all_critical()
            # self.add_vulnerability_scatterplot()
            # self.add_vulnerability_table()
            # self.add_vulnerability_table_by_severity()
            # self.add_vulnerability_table_by_package()

            self.doc.generate_pdf(compiler_args=["-f"])
            logger.debug("Generated PDF: {}", self.path)
        finally:
            # NOTE: we could implement __enter__ and __exit__ to ensure
            # ALL temporary files are cleaned up (including generated pdf)
            self.delete_temp_files()

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
        self._add_longtable(tabledata, row_height=ROWHEIGHT_SINGLEROW)

    def add_table_image_info(self) -> None:
        tabledata = image_info(self.scan)
        self._add_longtable(tabledata, row_height=ROWHEIGHT_SINGLEROW)

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

    def _add_section_longtable(
        self,
        tabledata: TableData,
        numbering: bool = True,
        newpage: bool = True,
        **kwargs,
    ) -> None:
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
        if newpage:
            self.doc.append(NewPage())
        with self.doc.create(
            Section(tabledata.title, numbering=numbering)
        ) as section:  # type: Section
            if tabledata.description:
                section.append(tabledata.description)
            section = cast(Section, section)  # mypy
            self._add_longtable(tabledata, LongTabularx)

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

    def add_plot_mean_trend(self) -> None:
        """Attempts to add a mean CVSSv3 score trend plot to the document."""
        self.doc.append(NewPage())
        section = self.doc.create(Section("Trend"))
        if self.prev_scans:
            # Actually add the plot if we have previous scans to compare to
            self._do_add_plot_mean_trend(section)
        else:
            # Otherwise, just add a placeholder
            self._do_add_plot_mean_trend_none(section)

    def _do_add_plot_mean_trend_none(self, section: SectionContext) -> None:
        logger.info("No previous data to compare with.")
        with section:
            self.doc.append(
                NoEscape(
                    r"\begin{center} \textbf{No previous scans to compare to.} \end{center}"
                )
            )

    def _do_add_plot_mean_trend(self, section: SectionContext) -> None:
        """Adds a mean CVSSv3 score trend plot to the document by comparing
        the current scan to the previous scans and creating a scatter plot."""
        plot = scatter_mean_trend(self.scan, self.prev_scans, self.filename)
        self.plots.append(plot.path)

        with section:
            self.doc.append(plot.description)
            with self.doc.create(Figure(position="h")) as fig:
                fig.add_image(str(plot.path), width=NoEscape(r"\textwidth"))
                fig.add_caption(plot.caption)

    def add_table_statistics(self) -> None:
        """Adds a table with statistics about the scanned image(s)."""
        # TODO: rewrite using _add_section_longtable
        self.doc.append(NewPage())
        tabledata = statistics_table(self.scan)
        with self.doc.create(Section(tabledata.title)):
            table_spec = " ".join(["l"] * len(tabledata.header))
            with self.doc.create(
                LongTabularx(table_spec, row_height=ROWHEIGHT_SINGLEROW, booktabs=True)
            ) as table:  # type: LongTable
                table = cast(LongTabularx, table)
                init_longtable(table, tabledata.header)
                for row in tabledata.rows:
                    add_row(table, row)
            self.doc.append(NoEscape(italic(tabledata.description)))

    def add_plot_severity_piechart(self) -> None:
        """Adds pie chart of CVSS severity distribution."""
        self.doc.append(NewPage())
        plot = piechart_severity(self.scan, self.filename)
        self.plots.append(plot.path)

        with self.doc.create(Section(plot.title)):
            self.doc.append(plot.description)
            with self.doc.create(Figure(position="h")) as fig:
                fig.add_image(str(plot.path), width=NoEscape(r"\textwidth"))
                # fig.add_plot(width=NoEscape(r"0.5\textwidth"), *args, **kwargs)
                fig.add_caption(plot.caption)

    def add_plot_scatter_vuln_age(self) -> None:
        """Adds a scatter plot of vulnerability age vs. CVSSv3 score."""
        self.doc.append(NewPage())
        plot = scatter_vulnerability_age(self.scan, self.filename)
        self.plots.append(plot.path)

        with self.doc.create(Section(plot.title)):
            self.doc.append(plot.description)
            with self.doc.create(Figure(position="h")) as fig:
                fig.add_image(str(plot.path), width=NoEscape(r"\textwidth"))
                fig.add_caption(plot.caption)

    def add_table_exploitable_vulns(self) -> None:
        """Adds a table of exploitable vulnerabilities."""
        self.doc.append(NewPage())
        tabledata = exploitable_vulns(self.scan)
        if tabledata.rows:
            self._add_section_longtable(tabledata)
        else:
            with self.doc.create(Section(title=tabledata.title)):
                self.doc.append("No exploitable vulnerabilities found.")
