__version__ = "0.1.0"

# Patch in import path of auspex core
import os
import sys

from .main import app

# sys.path.append(os.path.abspath("/auspex/core"))
