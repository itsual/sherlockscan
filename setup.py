#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# setup.py

import setuptools
import os
import re

# --- Helper function to read version ---
def get_version(package):
    """
    Return package version as listed in `__version__` in `init.py`.
    """
    init_py = open(os.path.join(package, '__init__.py')).read()
    # Regex adjusted to handle variations in quote style and spacing
    match = re.search(r"""^__version__\s*=\s*['"]([^'"]+)['"]""", init_py, re.MULTILINE)
    if match:
        return match.group(1)
    else:
        raise RuntimeError(f"Unable to find version string in {package}/__init__.py")

# --- Read README for long description ---
def get_long_description():
    """Return the README."""
    # Check if README.md exists before trying to open it
    readme_path = "README.md"
    if not os.path.exists(readme_path):
        # Provide a default short description if README is missing
        # This is important for package builds (like wheels) that might happen
        # in environments where the README isn't present.
        return DESCRIPTION 
    try:
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        # Fallback if reading fails for any reason
        return DESCRIPTION


# --- Package Metadata ---
NAME = "sherlockscan"
VERSION = get_version("sherlockscan") # Read from sherlockscan/__init__.py
AUTHOR = "Arockia Liborious" # Updated Author
EMAIL = "arockialiborious@gmail.com" # Updated Email
DESCRIPTION = "A tool to analyze Python packages for potential security risks, focusing on DS/ML."
# Assign long description safely
try:
    LONG_DESCRIPTION = get_long_description()
except FileNotFoundError:
    LONG_DESCRIPTION = DESCRIPTION # Fallback if README not found during setup run
URL = "https://github.com/yourusername/sherlockscan" # TODO: Replace with actual repo URL
LICENSE = "MIT" # Match the license chosen (e.g., MIT)

# --- Dependencies ---
# List runtime dependencies. Development dependencies should go in requirements-dev.txt or similar.
INSTALL_REQUIRES = [
    "typer>=0.9.0,<1.0.0", # For the CLI
    "PyYAML>=6.0,<7.0",   # For parsing config files
    "packaging>=21.3",  # For requirement parsing and canonical names
    "toml>=0.10.2",     # For parsing pyproject.toml
    # Add other core runtime dependencies here if any arise
    # Note: importlib_metadata is standard lib >= 3.8, backport needed otherwise
    # but we specify python_requires='>=3.8' below.
]

# --- Setup Configuration ---
setuptools.setup(
    name=NAME,
    version=VERSION,
    author=AUTHOR,
    author_email=EMAIL,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown", # Important for PyPI rendering
    url=URL,
    license=LICENSE,

    # Define where to find the package source code
    packages=setuptools.find_packages(
        exclude=["tests", "tests.*", "*.tests", "*.tests.*"] # Exclude test directories
    ),

    # Specify Python version requirement
    python_requires='>=3.8', # Based on importlib.metadata usage

    # Specify runtime dependencies
    install_requires=INSTALL_REQUIRES,

    # Define the command-line script entry point
    entry_points={
        "console_scripts": [
            "sherlockscan = sherlockscan.cli:app", # command = package.module:typer_app_object
        ],
    },

    # Include non-code files specified in MANIFEST.in (like default configs)
    # You will need a MANIFEST.in file for this to work correctly when building sdists.
    include_package_data=True,

    # PyPI classifiers: https://pypi.org/classifiers/
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: Software Development :: Build Tools',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Quality Assurance',
        'Topic :: Utilities',


        # Pick your license as you wish
        'License :: OSI Approved :: MIT License', # Ensure this matches LICENSE variable

        # Specify the Python versions you support here.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',

        'Operating System :: OS Independent', # Or specify applicable OSes
    ],

    # Optional: Specify project URLs
    project_urls={
        'Bug Reports': f'{URL}/issues',
        'Source': URL,
        # 'Documentation': 'https://your-docs-url.com', # Add if you have separate docs
    },
)

