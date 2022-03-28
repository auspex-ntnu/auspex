from matplotlib.cm import get_cmap
from matplotlib.colors import Colormap

from ..types.nptypes import MplRGBAColor

# We use the RdYlGn CMAP but reverse it so it goes from Green to Red
DEFAULT_CMAP = get_cmap("RdYlGn")
DEFAULT_CMAP = DEFAULT_CMAP.reversed()
DEFAULT_CMAP._init()  # call _init() so we can access the _lut attribute


def get_cvss_color(score: float, cmap: Colormap = DEFAULT_CMAP) -> MplRGBAColor:
    idx = int((score / 10) * len(cmap._lut)) - 1
    return cmap._lut[idx]
