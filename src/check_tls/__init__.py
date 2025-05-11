"""Package metadata initialisation."""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version(__name__)
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"
__all__ = ["__version__"]
