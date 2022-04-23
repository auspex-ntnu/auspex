from matplotlib.cm import get_cmap
from matplotlib.colors import Colormap
import numpy as np
from matplotlib.colors import ListedColormap
import matplotlib as mpl

from ..types.nptypes import MplRGBAColor

# We use the RdYlGn CMAP but reverse it so it goes from Green to Red
DEFAULT_CMAP = get_cmap("RdYlGn")
DEFAULT_CMAP = DEFAULT_CMAP.reversed()
DEFAULT_CMAP._init()  # call _init() so we can access the _lut attribute
# Add "yellows" as a new colormap to the list of colormaps
try:
    N = 256
    yellow = np.ones((N, 4))
    yellow[:, 0] = np.linspace(255 / 256, 1, N)[::-1]  # R = 255
    yellow[:, 1] = np.linspace(232 / 256, 1, N)[::-1]  # G = 232
    yellow[:, 2] = np.linspace(11 / 256, 1, N)[::-1]  # B = 11
    mpl.colormaps.register(ListedColormap(yellow), name="Yellows")
except ValueError as e:
    if "already registered" in str(e):
        pass
    else:
        raise


def get_cvss_color(score: float, cmap: Colormap = DEFAULT_CMAP) -> MplRGBAColor:
    if not hasattr(cmap, "_lut"):
        cmap._init()  # call _init() so we can access the _lut attribute
    idx = int((score / 10) * len(cmap._lut)) - 1
    return cmap._lut[idx]
