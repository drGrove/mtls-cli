import os
import sys

from .__version__ import version

__author__ = "Danny Grove <danny@drgrovellc.com>"
__version__ = version

# Allows "import mtls" and "from mtls import <name>".
sys.path.extend([os.path.join(os.path.dirname(__file__), "..")])

from .cli import cli  # noqa
from .mtls import MutualTLS  # noqa
