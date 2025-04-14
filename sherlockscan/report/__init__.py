#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/report/__init__.py

import logging

# Configure logger for this module if needed, or rely on package logger
logger = logging.getLogger(__name__)

# Define supported output formats
SUPPORTED_FORMATS = {"json", "md"}

# Expose the main formatter functions directly under the 'sherlockscan.report' namespace
try:
    from .json_formatter import format_report_json
    from .markdown_formatter import format_report_markdown

    # Define what 'from sherlockscan.report import *' would import.
    __all__ = [
        "format_report_json",
        "format_report_markdown",
        "SUPPORTED_FORMATS",
    ]

except ImportError as e:
    logger.error(f"Could not import report formatters on package init: {e}")
    __all__ = ["SUPPORTED_FORMATS"] # Only expose constants if imports fail


logger.debug("SherlockScan report module initialized.")


