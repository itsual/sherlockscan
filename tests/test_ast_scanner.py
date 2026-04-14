#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/test_ast_scanner.py

import unittest
import tempfile
import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

# Assume sherlockscan is installed or PYTHONPATH is set correctly
from sherlockscan.scanner.ast_scanner import scan_file_ast

# Disable logging during tests unless debugging
logging.disable(logging.CRITICAL)

class TestAstScanner(unittest.TestCase):
    """Unit tests for the ast_scanner module."""

    def _create_temp_file(self, content: str) -> Path:
        """Helper to create a temporary python file."""
        # Use delete=False to handle file closing on Windows before scanning
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False, encoding='utf-8')
        temp_file.write(content)
        temp_file.close() # Close the file so it can be reopened by the scanner
        return Path(temp_file.name)

    def _assert_finding_present(self, findings: List[Dict[str, Any]], expected_type: str, expected_severity: str, expected_line: Optional[int] = None):
        """Helper to assert if a specific type of finding is present."""
        found = False
        for finding in findings:
            match = (
                finding.get("type") == expected_type and
                finding.get("severity") == expected_severity and
                (expected_line is None or finding.get("line_number") == expected_line)
            )
            if match:
                found = True
                break
        self.assertTrue(found, f"Expected finding type='{expected_type}', severity='{expected_severity}'" + (f" on line {expected_line}" if expected_line else "") + " not found.")

    def test_risky_calls(self):
        """Test detection of direct risky function calls."""
        code = """
import os
import pickle

eval('print("hello")') # Line 5
os.system('ls')       # Line 6
exec('a=1')           # Line 7
pickle.loads(b'data') # Line 8
compile('x=1', '', 'exec') # Line 9
"""
        temp_file_path = self._create_temp_file(code)
        try:
            findings = scan_file_ast(str(temp_file_path))
            self.assertGreater(len(findings), 4, "Should find multiple risky calls") # pickle import + calls
            self._assert_finding_present(findings, "Risky Call", "CRITICAL", 5) # eval
            self._assert_finding_present(findings, "Subprocess Execution", "CRITICAL", 6) # os.system
            self._assert_finding_present(findings, "Risky Call", "CRITICAL", 7) # exec
            self._assert_finding_present(findings, "Insecure Deserialization", "CRITICAL", 8) # pickle.loads
            self._assert_finding_present(findings, "Risky Call", "HIGH", 9) # compile
            # Also check for pickle import finding
            self._assert_finding_present(findings, "Insecure Deserialization", "CRITICAL", 3) # import pickle
        finally:
            os.remove(temp_file_path) # Clean up

    def test_risky_imports(self):
        """Test detection of risky module imports."""
        code = """
import requests # Line 2
import socket   # Line 3
import ctypes   # Line 4
import subprocess # Line 5
import ftplib   # Line 6
import importlib # Line 7
import shelve   # Line 8
from http.client import HTTPConnection # Line 9
"""
        temp_file_path = self._create_temp_file(code)
        try:
            findings = scan_file_ast(str(temp_file_path))
            self.assertEqual(len(findings), 8, "Should find 8 risky imports")
            self._assert_finding_present(findings, "Network Activity", "MEDIUM", 2) # requests
            self._assert_finding_present(findings, "Network Activity", "MEDIUM", 3) # socket
            self._assert_finding_present(findings, "Dynamic Loading", "HIGH", 4) # ctypes
            self._assert_finding_present(findings, "Subprocess Execution", "HIGH", 5) # subprocess
            self._assert_finding_present(findings, "Network Activity", "MEDIUM", 6) # ftplib
            self._assert_finding_present(findings, "Dynamic Loading", "MEDIUM", 7) # importlib
            self._assert_finding_present(findings, "Insecure Deserialization", "HIGH", 8) # shelve
            self._assert_finding_present(findings, "Network Activity", "MEDIUM", 9) # http.client (from import)
        finally:
            os.remove(temp_file_path)

    def test_aliased_imports_calls(self):
        """Test detection works with aliased imports and calls."""
        code = """
import os as operating_system # Line 2
import pickle as cereal       # Line 3
import requests as req        # Line 4

operating_system.system('ls') # Line 6
data = cereal.loads(b'test')  # Line 7
req.get('http://example.com') # Line 8 - Note: Call itself isn't flagged, only import
"""
        temp_file_path = self._create_temp_file(code)
        try:
            findings = scan_file_ast(str(temp_file_path))
            # Expect findings for the imports and the aliased calls to os.system and pickle.loads
            self.assertGreaterEqual(len(findings), 3, "Should find at least 3 issues (imports + calls)")
            # Check imports
            self._assert_finding_present(findings, "Insecure Deserialization", "CRITICAL", 3) # import pickle as cereal
            self._assert_finding_present(findings, "Network Activity", "MEDIUM", 4) # import requests as req
            # Check aliased calls
            self._assert_finding_present(findings, "Subprocess Execution", "CRITICAL", 6) # operating_system.system
            self._assert_finding_present(findings, "Insecure Deserialization", "CRITICAL", 7) # cereal.loads
            # Note: req.get() itself isn't directly in RISKY_CALLS, so only the import is flagged by current logic
        finally:
            os.remove(temp_file_path)

    def test_clean_file(self):
        """Test scanning a file with no risky patterns."""
        code = """
import math

def calculate_area(radius):
    return math.pi * radius ** 2

result = calculate_area(5)
print(result)
"""
        temp_file_path = self._create_temp_file(code)
        try:
            findings = scan_file_ast(str(temp_file_path))
            self.assertEqual(len(findings), 0, "Should find no issues in a clean file")
        finally:
            os.remove(temp_file_path)

    def test_syntax_error_file(self):
        """Test scanning a file with Python syntax errors."""
        code = """
import os

def my_func(
    print("This is invalid syntax")
"""
        temp_file_path = self._create_temp_file(code)
        try:
            # Suppress expected ERROR log during this test
            logging.disable(logging.ERROR)
            findings = scan_file_ast(str(temp_file_path))
            logging.disable(logging.CRITICAL) # Re-enable default suppression
            self.assertEqual(len(findings), 0, "Should return no findings for a file with syntax errors")
            # Ideally, check logs or raise specific exception, but empty list is MVP behavior
        finally:
            os.remove(temp_file_path)

    def test_file_not_found(self):
        """Test scanning a non-existent file path."""
         # Suppress expected ERROR log during this test
        logging.disable(logging.ERROR)
        findings = scan_file_ast("non_existent_path_for_testing.py")
        logging.disable(logging.CRITICAL) # Re-enable default suppression
        self.assertEqual(len(findings), 0, "Should return no findings if file not found")

    def test_nested_calls(self):
        """Test detection within nested structures like classes/functions."""
        code = """
import os
import pickle

class MyProcessor:
    def run_command(self, cmd):
        os.system(cmd) # Line 7

    def load_data(self, path):
        with open(path, 'rb') as f:
            return pickle.load(f) # Line 11

def top_level_exec():
    exec('print("top level")') # Line 14
"""
        temp_file_path = self._create_temp_file(code)
        try:
            findings = scan_file_ast(str(temp_file_path))
            self.assertGreaterEqual(len(findings), 3) # pickle import + 3 calls
            self._assert_finding_present(findings, "Subprocess Execution", "CRITICAL", 7) # os.system in method
            self._assert_finding_present(findings, "Insecure Deserialization", "CRITICAL", 11) # pickle.load in method
            self._assert_finding_present(findings, "Risky Call", "CRITICAL", 14) # exec in function
            self._assert_finding_present(findings, "Insecure Deserialization", "CRITICAL", 3) # import pickle
        finally:
            os.remove(temp_file_path)


if __name__ == '__main__':
    unittest.main()

