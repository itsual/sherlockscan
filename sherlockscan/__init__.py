# sherlockscan/__init__.py

import logging
from logging import NullHandler

# --- Package Version ---
# Define package version in one place. Read dynamically in setup.py/pyproject.toml.
__version__ = "0.1.0" # Initial MVP version


# --- Configure Library Logging ---
# Set up a null handler for the root logger of this package.
# This prevents the library from outputting log messages if the consuming
# application has not configured logging. Applications using sherlockscan
# should configure their own logging handlers.
logging.getLogger(__name__).addHandler(NullHandler())
# Optional: Set a default level for the library's logger if needed during development
# logging.getLogger(__name__).setLevel(logging.INFO)


# --- Expose Key Public Elements (Optional but often useful) ---
# Make custom exceptions easily accessible directly from the package.
try:
    from .exceptions import (
        SherlockScanError,
        ConfigError,
        PackageNotFoundError,
        ScannerError,
        ReportFormattingError
    )

    # Define what 'from sherlockscan import *' would import (generally discouraged)
    # But also serves as documentation for the public API elements exposed here.
    __all__ = [
        "__version__",
        "SherlockScanError",
        "ConfigError",
        "PackageNotFoundError",
        "ScannerError",
        "ReportFormattingError",
        # Add other core functions/classes intended for public library use here if desired
        # e.g., maybe a high-level 'scan_package' function later?
    ]

except ImportError as e:
    # This might happen during initial setup or if structure changes.
    logging.getLogger(__name__).error(f"Could not import submodules on package init: {e}")
    __all__ = ["__version__"] # Only expose version if imports fail


# --- Optional Package-Level Initialization ---
# Avoid complex logic here if possible. Keep it lightweight.
# Example: logging.getLogger(__name__).debug(f"SherlockScan package ({__version__}) loaded.")

