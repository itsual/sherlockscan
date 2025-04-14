#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/exceptions.py

"""
Custom exception classes for the SherlockScan application.
"""

class SherlockScanError(Exception):
    """Base class for all SherlockScan custom exceptions."""
    def __init__(self, message="An error occurred in SherlockScan"):
        self.message = message
        super().__init__(self.message)

class ConfigError(SherlockScanError):
    """Exception raised for errors in loading or parsing configuration files."""
    def __init__(self, config_path: str, reason: str):
        self.config_path = config_path
        self.reason = reason
        message = f"Configuration error in '{config_path}': {reason}"
        super().__init__(message)

class PackageNotFoundError(SherlockScanError):
    """Exception raised when the target package cannot be found or accessed."""
    def __init__(self, package_target: str):
        self.package_target = package_target
        message = f"Target package '{package_target}' could not be found or accessed."
        super().__init__(message)

class ScannerError(SherlockScanError):
    """Exception raised for general errors during the scanning process."""
    def __init__(self, scanner_name: str, file_path: str = None, reason: str = "An unspecified error occurred"):
        self.scanner_name = scanner_name
        self.file_path = file_path
        self.reason = reason
        location = f" in file '{file_path}'" if file_path else ""
        message = f"Scanner error in '{scanner_name}'{location}: {reason}"
        super().__init__(message)

class ReportFormattingError(SherlockScanError):
    """Exception raised for errors during report formatting."""
    def __init__(self, format_type: str, reason: str):
        self.format_type = format_type
        self.reason = reason
        message = f"Error formatting report as '{format_type}': {reason}"
        super().__init__(message)

# Example of how these might be used (do not run this directly):
# if __name__ == '__main__':
#     try:
#         # Simulate an error
#         raise ConfigError("config/risk_patterns.yaml", "Invalid YAML syntax")
#     except SherlockScanError as e:
#         print(f"Caught SherlockScan specific error: {e}")
#     except Exception as e:
#         print(f"Caught general error: {e}")


