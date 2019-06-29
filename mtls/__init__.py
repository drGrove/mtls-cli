import os
import sys

from pkg_resources import get_distribution, DistributionNotFound

__author__ = "Danny Grove <danny@drgrovellc.com>"

# Allows "import mtls" and "from mtls import <name>".
sys.path.extend([os.path.join(os.path.dirname(__file__), "..")])

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    __version__ = "dev"

from .cli import cli  # noqa
from .mtls import MutualTLS  # noqa
