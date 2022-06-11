from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import matplotlib
from auspex_core.docker.models import ImageTimeMode
from auspex_core.models.scan import ReportData

matplotlib.use("Agg")  # disable GUI
import matplotlib.dates as mdates
import matplotlib.pyplot as plt  # noqa
import numpy as np
from sanitize_filename import sanitize

from ...cve import CVSS_DATE_BRACKETS
from ...types.protocols import ScanType
from ...utils.matplotlib import DEFAULT_CMAP
from .models import PlotData, PlotType


def piechart_severity(
    report: ScanType, basename: Optional[str] = None, exploitable: bool = False
) -> PlotData:
    """Generates a pie chart of the severity distribution of vulnerabilities.

    Parameters
    ----------
    report : `ScanType`
        A report, either a single report or an aggregate report.
    basename : `Optional[str]`
        The basename of the output file.
    Returns
    -------
    `PlotData`
        A plot data object containing everything required to insert
        the plot into the report.
    """
    e = "Exploitable " if exploitable else ""
    title = f"Distribution of {e}Vulnerabilities by Severity"
    p = PlotData(
        title=title,
        description="No vulnerabilities found.",
        caption=title,
        path=None,
        plot_type=PlotType.PIE,
    )

    fig, ax = plt.subplots()

    size = 0.3
    if exploitable:
        dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        vulns = report.get_exploitable()
        for vuln in vulns:
            sev = vuln.severity.lower()
            if dist.get(sev) is not None:
                dist[sev] += 1

    else:
        dist = report.get_distribution_by_severity()

    if all(v == 0 for v in dist.values()):
        return p

    labels = [d.title() for d in dist.keys()]
    values = [d for d in dist.values()]

    def get_colors(cmapname):
        return plt.colormaps[cmapname]([150, 125, 100])

    low = get_colors("Greens")
    medium = get_colors("Yellows")  # assert this is init
    high = get_colors("Oranges")
    critical = get_colors("Reds")
    # colors = [low, medium, high, critical]

    colors = [low[0], medium[0], high[0], critical[0]]

    def labelfunc(pct, allvals):
        absolute = int(np.round(pct / 100.0 * np.sum(allvals)))
        return "{:.1f}%\n({:d})".format(pct, absolute)

    # Outer pie chart
    wedges, *_ = ax.pie(
        values,
        radius=1,
        colors=colors,
        wedgeprops=dict(width=0.7, edgecolor="black", linewidth=0.5),
        startangle=90,
        counterclock=False,
        autopct=lambda pct: labelfunc(pct, values),
    )
    #
    ax.legend(
        wedges,
        labels,
        title="Severity",
        loc="upper left",
        bbox_to_anchor=(1, 0, 0.5, 1),
    )

    # Save fig and store its filename
    # TODO: fix filename
    path = save_fig(fig, report, basename, "piechart_severity")
    p.path = path
    p.description = (
        f"The pie chart shows the distribution of {e.lower()}vulnerabilities by severity. "
        "Severities are grouped by colour, as described by the legend. "
        "Each slice of the pie denotes the percentage of the total, and sum of vulnerabilities for each severity."
    )
    return p


def scatter_mean_trend(
    report: ScanType, prev_reports: list[ReportData], basename: Optional[str] = None
) -> PlotData:
    """Generates a scatter plot of the mean and trend of the CVSS score.

    Parameters
    ----------
    report : `ScanType`
        A report, either a single report or an aggregate report.
    prev_reports : `list[ReportData]`
        A list of previous reports.
    basename : `Optional[str]`
        The basename of the output file.

    Returns
    -------
    `PlotData`
        A plot data object containing everything required to insert
        the plot into the report.
    """

    p = PlotData(
        title="CVSSv3 Mean Score Trend",
        caption="CVSSv3 Mean Score Over Time",
        description="No previous reports to compare with.",
        plot_type=PlotType.SCATTER,
    )
    if len(prev_reports) == 0:
        return p

    fig, ax = plt.subplots()

    # Set up axes and labels
    ax.set_title("CVSSv3 Mean Score Over Time")
    ax.set_xlabel("Image Creation Time")
    ax.set_ylabel("CVSSv3 Mean Score")
    ax.set_ylim(0, 10)

    # Plot data
    scans = []  # type: list[ScanType]
    # TODO: move this timezone fixing to a separate function

    for scan in prev_reports + [report]:  # type: ScanType
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
    # TODO: specify default size of points
    ax.scatter(time, score)

    # Add newest report to the plot with a different color
    ax.scatter(
        [report.get_timestamp(image=True, mode=ImageTimeMode.CREATED)],
        [report.cvss.mean],
        color="#5acf1b",
        s=[100],  # TODO: find out default size, and have this be 1.5x that
    )

    # Format dates
    # Make ticks on occurrences of each month:
    ax.xaxis.set_major_locator(mdates.MonthLocator())
    # Get only the month to show in the x-axis:
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    # '%b' means month as locale’s abbreviated name

    # Trend line
    time_ts = [t.timestamp() for t in time]
    z = np.polyfit(time_ts, score, 1)
    poly = np.poly1d(z)
    ax.plot(time, poly(time_ts), color="r")

    # Add legend and grid
    fig.legend(["Previous Reports", "Current Report"])
    ax.grid(True)
    ax.set_axisbelow(True)

    # Save fig and store its filename
    p.path = save_fig(fig, report, basename, "scatter_mean_trend")
    nreports = len(prev_reports) + 1  # prev + current
    p.description = (
        f"Mean CVSSv3 score trend for the {nreports} most recent reports. "
        "Each data point in blue represents a previous scan. "
        "The current scan is represented by a green dot. "
        "The red line is the trend and shows whether the security state is improving or worsening over time. "
    )
    return p


def scatter_vulnerability_age(
    report: ScanType, basename: Optional[str] = None
) -> PlotData:
    """Generates a scatter plot of the vulnerability age.

    Parameters
    ----------
    report : `ScanType`
        A report, either a single report or an aggregate report.
    basename : `Optional[str]`
        The basename of the output file.


    Returns
    -------
    `PlotData`
        A plot data object containing everything required to insert
        the plot into the report.
    """
    fig, ax = plt.subplots()

    # Set up axes and labels
    ax.set_title("Vulnerability Age")
    ax.set_xlabel("Publication Time")
    ax.set_ylabel("CVSSv3 Score")
    ax.set_ylim(0, 10)

    # Plot data
    vulns = report.get_vulns_age_score_color()
    age = [v.timestamp for v in vulns]
    score = [v.score for v in vulns]
    color = [v.color for v in vulns]

    ax.scatter(age, score, c=color, cmap=DEFAULT_CMAP)
    ticks = [d.date.days for d in CVSS_DATE_BRACKETS]

    # # Format dates
    # age_days = [(datetime.utcnow().replace(tzinfo=d.tzinfo) - d).days for d in age]
    # maxdays = max(age_days)
    # if max(ticks) < maxdays:
    #     ticks.insert(0, maxdays + 30)
    # x = range(len(ticks))
    # # ax.xticks(x, ticks)
    # ax.set_xticks(x, ticks)

    # Set x axis formatter
    # Make ticks on occurrences of each month:
    # ax.xaxis.set_major_locator(mdates.YearLocator())
    # Get only the month to show in the x-axis:
    # ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    ax.xaxis.set_major_formatter(mdates.AutoDateFormatter(mdates.YearLocator()))
    ax.grid(True)
    ax.set_axisbelow(True)
    # '%b' means month as locale’s abbreviated name

    description = (
        "The age of unpatched vulnerabilities found and their corresponding CVSS scores. "
        "Each dot represents a vulnerability and is color coded, following the same style as the pie chart. "
        "The age of a vulnerability is based on its publication time. "
    )

    path = save_fig(fig, report, basename, "plot_vuln_age")
    return PlotData(
        title="Age of Unpatched Vulnerabilities",
        caption="Age of Unpatched Vulnerabilities",
        description=description,
        path=path,
        plot_type=PlotType.SCATTER,
    )


def save_fig(
    fig: plt.Figure,
    report: ScanType,
    basename: Optional[str],
    suffix: str,
    filetype: str = "pdf",
    close_after: bool = True,
) -> Path:
    """Saves a figure to a file.

    Parameters
    ----------
    fig : `plt.Figure`
        The figure to save.
    basename : `str`
        The basename of the output file.

    Returns
    -------
    `Path`
        Path to the generated figure.
    """
    if not basename:
        basename = report.id.replace(" ", "_").replace("/", "_")
    fig_filename = f"{basename}_{suffix}"
    if filetype:
        fig_filename = f"{fig_filename}.{filetype}"
    fig_filename = sanitize(fig_filename)
    path = Path(fig_filename).absolute()
    fig.savefig(str(path))
    if close_after:
        plt.close(fig)
    return path
