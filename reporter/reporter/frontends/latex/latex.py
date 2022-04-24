import asyncio
from pathlib import Path
from typing import Any, ContextManager, cast

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
)
from pylatex.utils import NoEscape, bold, italic
from sanitize_filename import sanitize

from ...types import ScanType, ScanTypeSingle
from ..shared.plots import (
    piechart_severity,
    scatter_mean_trend,
    scatter_vulnerability_age,
)
from ..shared.tables import statistics_table, top_vulns_table
from .table import init_longtable

# TODO: support aggregate scans


async def create_document(
    scan: ScanTypeSingle, prev_scans: list[ReportData]
) -> "LatexDocument":
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _do_create_document, scan, prev_scans)


def _do_create_document(
    scan: ScanTypeSingle, prev_scans: list[ReportData]
) -> "LatexDocument":
    """NOTE: blocking"""
    d = LatexDocument(scan, prev_scans)
    d.generate_pdf()
    return d


SectionContext = ContextManager[Any]


class LatexDocument:
    filename: str
    plots: list[Path]
    doc: Document
    scan: ScanTypeSingle
    prev_scans: list[ReportData]

    def __init__(self, scan: ScanTypeSingle, prev_scans: list[ReportData]) -> None:
        # NOTE: Very important to not have spaces in the filename
        # otherwise the PDF will not be generated.
        # PyLatex (or LaTeX itself) does not handle it well.
        # TODO: make self.filename a Path and check if we can write to it?
        self.filename = f"/tmp/{sanitize(scan.id)}".replace(" ", "_")
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
            self.add_preamble()
            self.add_header()
            self.add_mean_trend_plot()
            self.add_statistics_table()
            self.add_top_vuln_table()
            self.add_top_vuln_upgradable_table()
            self.add_severity_piechart()
            self.add_scatter_vuln_age()
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
        # using all 512MB of memory by carelessly writing to the in-memory filesystem.
        # As a precautionary measure, we make sure all temporary files are cleaned up.
        for plot in self.plots:
            Path(plot).unlink(missing_ok=True)

    def add_preamble(self) -> None:
        self.doc.preamble.append(Command("title", self.scan.image.image))
        self.doc.preamble.append(Command("author", "Auspex"))
        self.doc.preamble.append(Command("date", NoEscape(r"\today")))
        self.doc.append(NoEscape(r"\maketitle"))

    def add_header(self):
        # Add document header
        header = PageStyle("header")

        # Create left header
        with header.create(Head("L")):
            header.append("Page date: ")
            header.append(LineBreak())
            header.append("R3")
        # Create center header
        with header.create(Head("C")):
            header.append("Company")
        # Create right header
        with header.create(Head("R")):
            header.append(simple_page_number())
        # Create left footer
        with header.create(Foot("L")):
            header.append("Left Footer")
        # Create center footer
        with header.create(Foot("C")):
            header.append("Center Footer")
        # Create right footer
        with header.create(Foot("R")):
            header.append("Right Footer")

        self.doc.preamble.append(header)
        self.doc.change_document_style("header")

    def add_severity_piechart(self) -> None:
        """Adds pie chart of CVSS severity distribution."""
        plot = piechart_severity(self.scan, self.filename)
        self.plots.append(plot.path)
        with self.doc.create(Section(plot.title)):
            self.doc.append(plot.description)
            with self.doc.create(Figure(position="h")) as fig:
                fig.add_image(str(plot.path), width=NoEscape(r"\textwidth"))
                # fig.add_plot(width=NoEscape(r"0.5\textwidth"), *args, **kwargs)
                fig.add_caption(plot.caption)
            self.doc.append("Created using matplotlib.")

    def add_top_vuln_table(self) -> None:
        """Adds a table with the top N vulnerabilities."""
        self._add_top_vulnerability_table(upgradable=False)

    def add_top_vuln_upgradable_table(self) -> None:
        """Adds a table with the top N upgradable vulnerabilities."""
        self._add_top_vulnerability_table(upgradable=True)

    def _add_top_vulnerability_table(self, upgradable: bool, maxrows: int = 5) -> None:
        """Adds a table with the top N vulnerabilities.

        Parameters
        ----------
        upgradable : `bool`
            Whether to only show upgradable vulnerabilities
        maxrows : `int`
            Maximum number of rows to show
            TODO: make this configurable
        """
        data = top_vulns_table(self.scan, upgradable=upgradable, maxrows=maxrows)
        if not data.rows:
            logger.info(f"No vulnerabilities to report for report {self.scan.id}")
            return

        with self.doc.create(Section(data.title)) as section:  # type: Section
            section = cast(Section, section)  # mypy
            table_spec = " ".join(["l"] * len(data.header))
            with self.doc.create(LongTabularx(table_spec, booktabs=True)) as table:
                table = cast(LongTabularx, table)
                init_longtable(table, data.header)
                for row in data.rows:
                    table.add_row([NoEscape(c) for c in row])

    def add_mean_trend_plot(self) -> None:
        """Attempts to add a mean CVSSv3 score trend plot to the document."""
        section = self.doc.create(Section("Trend"))
        if self.prev_scans:
            # Actually add the plot if we have previous scans to compare to
            self._do_add_mean_trend_plot(section)
        else:
            # Otherwise, just add a placeholder
            self._do_add_mean_trend_plot_none(section)

    def _do_add_mean_trend_plot_none(self, section: SectionContext) -> None:
        logger.info("No previous data to compare with.")
        with section:
            self.doc.append(
                NoEscape(
                    r"\begin{center} \textbf{No previous scans to compare to.} \end{center}"
                )
            )

    def _do_add_mean_trend_plot(self, section: SectionContext) -> None:
        """Adds a mean CVSSv3 score trend plot to the document by comparing
        the current scan to the previous scans and creating a scatter plot."""
        plot = scatter_mean_trend(self.scan, self.prev_scans, self.filename)
        self.plots.append(plot.path)

        with section:
            self.doc.append(plot.description)
            with self.doc.create(Figure(position="h")) as fig:
                fig.add_image(str(plot.path), width=NoEscape(r"\textwidth"))
                fig.add_caption(plot.caption)
            self.doc.append("Created using matplotlib.")

    def add_statistics_table(self) -> None:
        tabledata = statistics_table(self.scan)
        with self.doc.create(Section(tabledata.title)):
            table_spec = " ".join(["l"] * len(tabledata.header))
            with self.doc.create(
                LongTabularx(table_spec, row_height=1.5, booktabs=True)
            ) as table:  # type: LongTable
                table = cast(LongTabularx, table)
                init_longtable(table, tabledata.header)
                for row in tabledata.rows:
                    table.add_row([NoEscape(c) for c in row])

    def add_scatter_vuln_age(self) -> None:
        plot = scatter_vulnerability_age(self.scan, self.filename)
        self.plots.append(plot.path)

        with self.doc.create(Section(plot.title)):
            self.doc.append(plot.description)
            with self.doc.create(Figure(position="h")) as fig:
                fig.add_image(str(plot.path), width=NoEscape(r"\textwidth"))
                fig.add_caption(plot.caption)
            self.doc.append("Created using matplotlib.")
