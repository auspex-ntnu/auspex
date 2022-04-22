import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ContextManager, Union, cast
from auspex_core.models.gcr import ImageTimeMode
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
    LongTable,
    MultiColumn,
    LongTabularx,
)
from pylatex.utils import NoEscape, bold, italic
from sanitize_filename import sanitize

matplotlib.use("agg")  # Not to use X server. For TravisCI.
import matplotlib.pyplot as plt  # noqa
import matplotlib.dates as mdates
import numpy as np
from auspex_core.models.scan import ReportData

from ...cve import CVSS_DATE_BRACKETS
from ...backends.snyk.model import SnykContainerScan
from ...types import ScanType, ScanTypeSingle
from ...utils.matplotlib import DEFAULT_CMAP
from ...config import AppConfig
from .tables import init_longtable
from ..shared.format import format_decimal
from ..shared.vulnerabilities import top_vulns_table
from ..shared.statistics import statistics_box

import random

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
    plots: list[str]
    doc: Document
    scan: ScanTypeSingle
    prev_scans: list[ReportData]

    def __init__(self, scan: ScanTypeSingle, prev_scans: list[ReportData]) -> None:
        # NOTE: Very important to not have spaces in the filename
        # otherwise the PDF will not be generated.
        # PyLatex (or LaTeX itself) does not handle it well.
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
        try:
            self.add_preamble()
            self.add_header()
            self.add_mean_trend_plot()
            self.add_statistics_box()
            self.add_top_vuln_table()
            self.add_top_vuln_upgradable_table()
            self.add_severity_piechart()
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
        # Delete plots after generating PDF
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
        plt.clf()
        fig, ax = plt.subplots()

        size = 0.3
        dist = self.scan.get_distribution_by_severity()
        labels = [d.title() for d in dist.keys()]
        values = [d for d in dist.values()]

        def get_colors(cmapname):
            return plt.colormaps[cmapname]([150, 125, 100])

        # plt.colormaps["Yellows"] = yellow_cmp

        low = get_colors("Greens")
        medium = get_colors("Yellows")
        high = get_colors("Oranges")
        critical = get_colors("Reds")
        # colors = [low, medium, high, critical]

        colors = [low[0], medium[0], high[0], critical[0]]

        # Outer pie chart
        wedges, texts = ax.pie(
            values,
            radius=1,
            colors=colors,
            wedgeprops=dict(width=0.7, edgecolor="black", linewidth=0.5),
            startangle=90,
            counterclock=False,
        )
        #
        plt.legend(
            wedges,
            ["Low", "Medium", "High", "Critical"],
            title="Severity",
            loc="upper left",
            bbox_to_anchor=(1, 0, 0.5, 1),
        )

        # TODO: Add wedge labels
        # Total number of vulnerabilities as well

        ax.set(aspect="equal", title="Pie plot with `ax.pie`")
        # Save fig and store its filename
        fig_filename = f"{self.filename}_pie.pdf"
        plt.savefig(fig_filename)
        self.plots.append(fig_filename)

        with self.doc.create(Section("Pie")):
            self.doc.append("mmm pie")
            with self.doc.create(Figure(position="htbp")) as plot:
                plot.add_image(fig_filename, width=NoEscape(r"\textwidth"))
                # plot.add_plot(width=NoEscape(r"0.5\textwidth"), *args, **kwargs)
                plot.add_caption("I am a caption.")
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
                    table.add_row(row)

    def add_top_common_table(self) -> None:
        """NOTE: UNUSED + UNSTABLE"""
        with self.doc.create(Section("Top 5 Most Common Vulnerabilities")):
            maxrows = 5
            columns = [
                "Vulnerability",  # Name
                "CVSS ID",  # ID
                "CVSS Score",  # 0-10
                "Upgradable",  # Yes/No
                "Count",  # n times
            ]
            ncols = len(columns)
            table_spec = " ".join(["l"] * ncols)
            with self.doc.create(LongTable(table_spec)) as table:  # type: LongTable
                table = cast(LongTable, table)
                init_longtable(table, columns)
                most_severe = self.scan.most_severe_n(maxrows)
                for vuln in most_severe:
                    table.add_row(
                        (
                            NoEscape(vuln.title),
                            NoEscape(vuln.get_id()),
                            NoEscape(format_decimal(vuln.get_cvss_score())),
                            NoEscape(vuln.is_upgradable),
                            NoEscape(f"{vuln.count}"),
                        )
                    )
                # if not 5: pad out table with empty rows

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

        # clear any previous matplotlib plots
        # TODO: check if we need to do it differently when using the
        # object oriented interface
        plt.clf()

        fig, ax = plt.subplots()

        # Set up axes and labels
        ax.set_title("CVSSv3 Mean Score Over Time")
        ax.set_xlabel("Image Creation Time")
        ax.set_ylabel("CVSSv3 Mean Score")
        ax.set_ylim(0, 10)

        # Plot data
        scans = []  # type: list[ScanType]
        # TODO: move this timezone fixing to a separate function
        for scan in self.prev_scans + [self.scan]:  # type: ScanType
            if scan.timestamp.tzinfo is None:
                scan.timestamp = scan.timestamp.replace(tzinfo=timezone.utc)
            scans.append(scan)
        scans = sorted(scans, key=lambda x: x.timestamp)

        ## IMPORTANT NOTE REGARDING DATES:
        #
        # We are plotting the mean CVSSv3 score over time using the CREATION TIME
        # of each image as the X-axis values, NOT the time of when the scan took place.
        #
        # This is because we want to be able to support re-scanning older images
        # without these images changing position on the X-axis (time) on the plot,
        # and thus influencing the CVSS score trend line.
        time = [
            scan.get_timestamp(image=True, mode=ImageTimeMode.CREATED) for scan in scans
        ]
        score = [scan.cvss.mean for scan in scans]
        ax.scatter(time, score)

        # Format dates
        # Make ticks on occurrences of each month:
        ax.xaxis.set_major_locator(mdates.MonthLocator())
        # Get only the month to show in the x-axis:
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
        # '%b' means month as locale’s abbreviated name

        # Trend line
        time_ts = [t.timestamp() for t in time]
        z = np.polyfit(time_ts, score, 1)
        p = np.poly1d(z)
        plt.plot(time, p(time_ts), color="r")

        # Add legend and grid
        plt.legend(["Score"])
        plt.grid(True)

        # Save fig and store its filename
        fig_filename = f"{self.filename}_plot_trend.pdf"
        plt.savefig(fig_filename)
        self.plots.append(fig_filename)

        with section:
            self.doc.append(
                f"Mean CVSSv3 score trend for the {len(scans)} most recent scans"
            )
            with self.doc.create(Figure(position="htbp")) as plot:
                plot.add_image(fig_filename, width=NoEscape(r"\textwidth"))
                # plot.add_plot(width=NoEscape(r"0.5\textwidth"), *args, **kwargs)
                plot.add_caption("I am a caption.")
            self.doc.append("Created using matplotlib.")

    def add_statistics_box(self) -> None:
        columns = [
            "Median CVSS Score",
            "Mean CVSS Score",
            "Standard Deviation",
            "Max CVSS Score",
            "Highest Severity",
        ]
        tabledata = statistics_box(self.scan)
        with self.doc.create(Section(tabledata.title)):
            table_spec = " ".join(["l"] * len(tabledata.header))
            with self.doc.create(
                LongTabularx(table_spec, row_height=1.5, booktabs=True)
            ) as table:  # type: LongTable
                table = cast(LongTabularx, table)
                init_longtable(table, columns)
                for row in tabledata.rows:
                    table.add_row(row)

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
