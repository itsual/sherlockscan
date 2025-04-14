#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/scanner/__init__.py

import logging

# Configure logger for this module if needed, or rely on package logger
logger = logging.getLogger(__name__)

# Expose the main scanning functions from each submodule directly
# under the 'sherlockscan.scanner' namespace for easier library use.
try:
    from .ast_scanner import scan_file_ast
    from .heuristics import scan_file_heuristics
    from .deps import scan_dependencies
    from .install_script_analyzer import scan_install_scripts, scan_setup_py, scan_pyproject_toml
    # Explainer is related but operates on results, might keep it separate
    # from .explainer import generate_overall_explanation

    # Define what 'from sherlockscan.scanner import *' would import.
    __all__ = [
        "scan_file_ast",
        "scan_file_heuristics",
        "scan_dependencies",
        "scan_install_scripts",
        "scan_setup_py",          # Expose sub-scanners too if useful
        "scan_pyproject_toml",    # Expose sub-scanners too if useful
        # "generate_overall_explanation", # Decide if explainer belongs here
    ]

except ImportError as e:
    logger.error(f"Could not import scanner submodules on package init: {e}")
    __all__ = [] # Empty if imports fail


logger.debug("SherlockScan scanner module initialized.")


