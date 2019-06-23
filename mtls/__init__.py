from pkg_resources import get_distribution, DistributionNotFound

__author__ = "Danny Grove <danny@drgrovellc.com>"

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    __version__ = "dev"
