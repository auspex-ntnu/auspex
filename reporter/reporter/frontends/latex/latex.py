import asyncio
from pathlib import Path
from typing import Union
from loguru import logger

import matplotlib
from pylatex import (
    Command,
    Document,
    Figure,
    Foot,
    Head,
    LargeText,
    LineBreak,
    MediumText,
    MiniPage,
    PageStyle,
    Section,
    Subsection,
    Tabular,
    simple_page_number,
)
from pylatex.utils import NoEscape, bold, italic
from sanitize_filename import sanitize

matplotlib.use("agg")  # Not to use X server. For TravisCI.
import matplotlib.pyplot as plt  # noqa
import numpy as np
from auspex_core.models.scan import ParsedScan

from ...backends.cve import CVSS_DATE_BRACKETS
from ...backends.snyk.model import SnykContainerScan
from ...types import ScanType
from ...utils.matplotlib import DEFAULT_CMAP


async def create_document(
    scan: ScanType, prev_scans: list[ParsedScan]
) -> "LatexDocument":
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _do_create_document, scan, prev_scans)


def _do_create_document(
    scan: ScanType, prev_scans: list[ParsedScan]
) -> "LatexDocument":
    """NOTE: blocking"""
    d = LatexDocument(scan, prev_scans)
    d.generate_pdf()
    return d


# TODO: move this function to a more appropriate module
def format_decimal(n: Union[int, float]) -> str:
    return f"{n:.2f}"


class LatexDocument:
    filename: str
    plots: list[str]
    doc: Document
    scan: ScanType
    prev_scans: list[ParsedScan]

    def __init__(self, scan: ScanType, prev_scans: list[ParsedScan]) -> None:
        self.filename = f"/tmp/{sanitize(scan.id)}"
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
            # "includeheadfoot": True
        }
        return Document(
            self.filename,
            page_numbers=True,
            geometry_options=geometry_options,
        )

    def generate_pdf(self) -> Document:
        self.add_preamble()
        self.add_statistics_box()
        self.add_trend_plot()
        self.doc.generate_pdf(compiler_args=["-f"])

        # Delete plots after generating PDF
        # Depending on how (non-)ephemeral these containers are, we could risk
        # using all 512MB of memory by carelessly writing to the in-memory filesystem.
        # As a precautionary measure, we make sure all temporary files are cleaned up.
        for plot in self.plots:
            Path(plot).unlink()

    def add_preamble(self) -> None:
        self.doc.preamble.append(Command("title", self.scan.image))
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

    def add_trend_plot(self) -> None:
        if not self.prev_scans:
            logger.info("No previous scans to compare to.")
            return

        fig = plt.figure(figsize=(8, 6))
        ax = fig.add_subplot(111)
        ax.set_title("Trend")
        ax.set_xlabel("Time")
        ax.set_ylabel("Value")
        ax.plot(
            [
                (scan.timestamp - self.scan.scanned).total_seconds()
                for scan in self.prev_scans
            ],
            [scan.cvss_mean for scan in self.prev_scans],
        )
        fig.tight_layout()

        # Save fig and store its filename
        fig_filename = f"{self.filename}_plot_trend.pdf"
        plt.savefig(fig_filename)
        self.plots.append(fig_filename)

        with self.doc.create(Section("Trend")):
            self.doc.append("Take a look at this beautiful plot:")
            with self.doc.create(Figure(position="htbp")) as plot:
                plot.add_image(fig_filename, width=NoEscape(r"\textwidth"))
                # plot.add_plot(width=NoEscape(r"0.5\textwidth"), *args, **kwargs)
                plot.add_caption("I am a caption.")
            self.doc.append("Created using matplotlib.")

        # fig.savefig(f"{self.filename}_trend.png")
        # self.plots.append(f"{self.filename}_trend.png")
        # self.doc.append(Figure(f"{self.filename}_trend.png"))

    def add_statistics_box(self) -> None:
        # with self.doc.create(Section("Vulnerability Distribution")):
        #     self.doc.append("Some text")
        with self.doc.create(Section("Statistics", False)):
            dist = self.scan.get_distribution_by_severity()
            prio = ["critical", "high", "medium", "low"]
            highest_severity = "low"  # default to low
            for p in prio:
                if dist.get(p):
                    highest_severity = p
                    break

            with self.doc.create(
                Tabular(
                    "l l",
                    row_height=1.5,
                    # col_space=10,
                    width=2,
                )
            ) as table:
                table.add_row(
                    "Median CVSS Score:",
                    format_decimal(self.scan.cvss_median),
                )
                table.add_row(
                    "Mean CVSS Score:",
                    format_decimal(self.scan.cvss_mean),
                )
                table.add_row(
                    "Standard Deviation:",
                    format_decimal(self.scan.cvss_stdev),
                ),
                table.add_row(
                    "Max CVSS Score:",
                    format_decimal(self.scan.cvss_max),
                ),
                table.add_row(
                    "Highest severity:",
                    highest_severity,
                ),

    # def add_factbox(self) -> None:
    #     pass

    def add_scatterplot(self) -> None:
        # age = ([9, 7, 8, 11, 15, 14, 18],)
        # severity = [4, 5, 8, 3, 2, 6, 9]
        asc = self.scan.get_vulns_age_score_color()
        age = [t[0] for t in asc]
        severity = [t[1] for t in asc]
        color = [t[2] for t in asc]

        plt.scatter(age, severity, c=color, cmap=DEFAULT_CMAP)
        plt.xlabel("Time unpatched since publication (days)")
        plt.ylabel("severity score")
        ticks = [d.date.days for d in CVSS_DATE_BRACKETS]
        if max(ticks) < max(age):
            ticks.insert(0, max(age) + 30)
        x = range(len(ticks))
        # plt.xticks(x, ticks)

        # Save fig and store its filename
        fig_filename = f"{self.filename}_vuln_scatter.pdf"
        plt.savefig(fig_filename)
        self.plots.append(fig_filename)

        with self.doc.create(Section("Scatterplot")):
            self.doc.append("Take a look at this beautiful plot:")
            with self.doc.create(Figure(position="htbp")) as plot:
                plot.add_image(fig_filename, width=NoEscape(r"\textwidth"))
                # plot.add_plot(width=NoEscape(r"0.5\textwidth"), *args, **kwargs)
                plot.add_caption("I am a caption.")
            self.doc.append("Created using matplotlib.")

    def add_plot(self, *args, **kwargs) -> None:
        sev = self.scan.severity_v3()
        columns = [s[0] for s in sev]
        data = [s[1] for s in sev]
        index = np.arange(len(columns)) + 0.3
        bar_width = 0.4

        # Add severity labels to ticks
        fig, ax = plt.subplots()
        ax.set_xticks(index, columns)
        plt.bar(index, data, bar_width)

        # Save fig and store its filename
        fig_filename = f"{self.filename}_fig.pdf"
        plt.savefig(fig_filename)
        self.plots.append(fig_filename)

        with self.doc.create(Section("I am a section")):
            self.doc.append("Take a look at this beautiful plot:")
            with self.doc.create(Figure(position="htbp")) as plot:
                plot.add_image(fig_filename, width=NoEscape(r"\textwidth"))
                # plot.add_plot(width=NoEscape(r"0.5\textwidth"), *args, **kwargs)
                plot.add_caption("I am a caption.")
            self.doc.append("Created using matplotlib.")
