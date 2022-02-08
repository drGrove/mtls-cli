import os
import sys

from pkg_resources import get_distribution, DistributionNotFound

__author__ = "Danny Grove <danny@drgrovellc.com>"
__version__ = "0.0.0-dev0"

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    pass

# Allows "import mtls" and "from mtls import <name>".
sys.path.extend([os.path.join(os.path.dirname(__file__), "..")])

from .cli import cli  # noqa
from .mtls import MutualTLS  # noqa
