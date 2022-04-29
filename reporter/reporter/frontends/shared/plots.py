from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from auspex_core.models.gcr import ImageTimeMode
from auspex_core.models.scan import ReportData

import matplotlib

matplotlib.use("Agg")  # disable GUI
import matplotlib.pyplot as plt  # noqa
import matplotlib.dates as mdates
import numpy as np
from sanitize_filename import sanitize

from ...types.protocols import ScanType
from ...utils.matplotlib import DEFAULT_CMAP
from ...cve import CVSS_DATE_BRACKETS
from .models import PlotData, PlotType


def piechart_severity(report: ScanType, basename: Optional[str] = None) -> PlotData:
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
    plt.clf()
    fig, ax = plt.subplots()

    size = 0.3
    dist = report.get_distribution_by_severity()
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
    ax.legend(
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
    # TODO: fix filename
    path = save_fig(fig, report, basename, "piechart_severity")
    return PlotData(
        title="Distribution of Vulnerabilities by Severity",
        path=path,
        caption="Distribution of Vulnerabilities by Severity",
        description="I am a description",
        plot_type=PlotType.PIE,
    )


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
    plt.clf()  # is this necessary when using subplots?

    fig, ax = plt.subplots()

    # Set up axes and labels
    ax.set_title("CVSSv3 Mean Score Over Time")
    ax.set_xlabel("Image Creation Time")
    ax.set_ylabel("CVSSv3 Mean Score")
    ax.set_ylim(0, 10)

    # Plot data
    scans = []  # type: list[ScanType]
    # TODO: move this timezone fixing to a separate function

    for scan in prev_reports:  # type: ScanType
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
    p = np.poly1d(z)
    ax.plot(time, p(time_ts), color="r")

    # Add legend and grid
    fig.legend(["Previous Reports", "Current Report"])
    ax.grid(True)
    ax.set_axisbelow(True)

    # Save fig and store its filename
    path = save_fig(fig, report, basename, "scatter_mean_trend")
    nreports = len(prev_reports) + 1  # prev + current
    title = f"Mean CVSSv3 score trend for the {nreports} most recent reports"
    return PlotData(
        title=title,
        caption="CVSSv3 Mean Score Over Time",
        description=title,
        path=path,
        plot_type=PlotType.SCATTER,
    )


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
    plt.clf()

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
    # '%b' means month as locale’s abbreviated name

    path = save_fig(fig, report, basename, "plot_vuln_age")
    return PlotData(
        title="Age of Unpatched Vulnerabilities",
        caption="Age of Unpatched Vulnerabilities",
        description="I am a description",
        path=path,
        plot_type=PlotType.SCATTER,
    )


def save_fig(
    fig: plt.Figure,
    report: ScanType,
    basename: Optional[str],
    suffix: str,
    filetype: str = "pdf",
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
    return path
