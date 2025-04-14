#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/config/__init__.py

import logging
from pathlib import Path
import importlib.resources as pkg_resources
# Use 'importlib.resources' for Python 3.7+
# For older versions, 'pkg_resources' from setuptools was used, but it's legacy.

# Configure logger for this module if needed, or rely on package logger
logger = logging.getLogger(__name__)

# Define constants for default config filenames
DEFAULT_RISK_PATTERNS_FILE = "risk_patterns.yaml"
DEFAULT_APPROVED_PACKAGES_FILE = "approved_packages.yaml"

def get_default_config_path(filename: str) -> Path:
    """
    Gets the path to a default configuration file packaged within the library.

    Uses importlib.resources to reliably find the file path even when the
    package is installed (e.g., in site-packages).

    Args:
        filename: The name of the configuration file (e.g., "risk_patterns.yaml").

    Returns:
        A pathlib.Path object pointing to the default configuration file.

    Raises:
        FileNotFoundError: If the specified default file cannot be found within the package.
        TypeError: If importlib.resources is unavailable (should not happen on Py >= 3.7).
    """
    try:
        # 'files()' returns a Traversable resource reader for the package
        # Available Python 3.9+ (preferred).
        # For 3.7, 3.8 use legacy 'path()' with context manager if needed,
        # but 'files()' is generally compatible via backports if installed.
        resource_path = pkg_resources.files('sherlockscan.config').joinpath(filename)
        
        # Verify the resource actually exists as a file within the package data
        # Note: resource_path might be a path inside a zip archive if installed from wheel
        if resource_path.is_file():
             logger.debug(f"Found default config file: {resource_path}")
             return Path(str(resource_path)) # Ensure it's a Path object
        else:
             # This case might occur if the file wasn't included in MANIFEST.in
             # or if the package structure is unexpected.
             logger.error(f"Default config file '{filename}' not found within the package resources at expected location.")
             raise FileNotFoundError(f"Default config file '{filename}' not found in package data.")
             
    except (AttributeError, TypeError, ModuleNotFoundError) as e:
        # Handle cases where importlib.resources might not be fully available
        # or the package structure is broken. Should be rare on supported Python versions.
        logger.exception(f"Could not access package resources using importlib.resources: {e}")
        raise TypeError("Could not access package resources. Ensure Python >= 3.7 and package is installed correctly.") from e
    except Exception as e:
        logger.exception(f"An unexpected error occurred finding default config '{filename}': {e}")
        # Re-raise FileNotFoundError for consistency if the file wasn't located
        raise FileNotFoundError(f"Could not determine path for default config file '{filename}'.") from e


def get_default_risk_patterns_path() -> Path:
    """Gets the path to the default risk_patterns.yaml file."""
    return get_default_config_path(DEFAULT_RISK_PATTERNS_FILE)

def get_default_approved_packages_path() -> Path:
    """Gets the path to the default approved_packages.yaml file."""
    return get_default_config_path(DEFAULT_APPROVED_PACKAGES_FILE)


# Define what 'from sherlockscan.config import *' would import.
__all__ = [
    "get_default_risk_patterns_path",
    "get_default_approved_packages_path",
    "DEFAULT_RISK_PATTERNS_FILE",
    "DEFAULT_APPROVED_PACKAGES_FILE"
]

# Example usage (for understanding, not typically run directly)
# if __name__ == '__main__':
#     try:
#         patterns_path = get_default_risk_patterns_path()
#         print(f"Default risk patterns path: {patterns_path}")
#         print(f"Exists: {patterns_path.exists()}") # Note: exists() might not work correctly if inside a zip file
#         print(f"Is file: {patterns_path.is_file()}")
#
#         approved_path = get_default_approved_packages_path()
#         print(f"Default approved packages path: {approved_path}")
#         print(f"Exists: {approved_path.exists()}")
#         print(f"Is file: {approved_path.is_file()}")
#
#     except Exception as e:
#         print(f"Error getting default config paths: {e}")


