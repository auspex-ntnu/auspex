__version__ = "0.1.0"

# Patch in import path of auspex core
import sys
import os

# sys.path.append(os.path.abspath("/auspex/core"))


from .main import app
