#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/integration/test_end_to_end.py

import unittest
import tempfile
import os
import json
import logging
import shutil
from pathlib import Path
from typing import Optional, Dict
from unittest.mock import patch # May still need minor mocking (e.g., package resolution if complex)

# Import the Typer app instance from cli.py
# Need to handle potential import errors if modules are not found
try:
    from typer.testing import CliRunner
    from sherlockscan.cli import app # The Typer app instance
    # Assume utils and exceptions are available via sherlockscan package
    from sherlockscan import utils 
    from sherlockscan.exceptions import PackageNotFoundError, SherlockScanError
    INTEGRATION_TEST_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import Typer or SherlockScan modules for Integration tests: {e}")
    print("Integration tests will be skipped.")
    INTEGRATION_TEST_AVAILABLE = False
    # Define dummy classes/vars if needed for file parsing
    class CliRunner: pass
    app = None

# Disable logging during tests unless debugging
# logging.basicConfig(level=logging.DEBUG) # Enable for debugging tests
logging.disable(logging.CRITICAL)

# --- Sample File Contents for Dummy Packages ---

RISKY_SETUP_PY_CONTENT = """
import os
from setuptools import setup
# Execute command during setup
os.system('echo "Risky setup!"')
setup(name='risky_pkg', version='1.0')
"""

RISKY_PYPROJECT_TOML_CONTENT = """
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[tool.setuptools.cmdclass]
build_py = "custom_build:BuildPyCommand"
"""

RISKY_MODULE_CONTENT = """
import pickle
import requests # Network activity

SECRET_KEY = "sk_live_very_secret_key_abc123" # Hardcoded Secret
PASSWORD = "password123" # Another secret

def load_data(path):
    # Insecure deserialization
    with open(path, 'rb') as f:
        return pickle.load(f)

def make_request():
    try:
        requests.get("http://example.com") # Network call
    except:
        pass # Ignore errors in dummy code

# High entropy
obfuscated = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Keyword
# TODO: security - fix this
"""

CLEAN_SETUP_PY_CONTENT = """
from setuptools import setup
setup(name='clean_pkg', version='1.0', install_requires=['requests'])
"""

CLEAN_MODULE_CONTENT = """
import math
# This code is safe
def add(a, b):
    return a + b
"""

RISKY_CONFIG_PATTERNS_YAML = """\
settings:
  entropy_threshold: 4.0
regex_patterns:
  - name: Stripe API Key Mock
    type: Hardcoded Secret
    pattern: 'sk_live_[a-zA-Z0-9]+'
    severity: CRITICAL
  - name: Simple Password Assignment
    type: Hardcoded Secret
    pattern: 'PASSWORD\\s*=\\s*"(.*?)"'
    severity: HIGH
keywords:
  - name: TODO Security
    type: Security Comment
    keyword: "TODO: security"
    severity: LOW
"""

RISKY_APPROVED_PACKAGES_YAML = """
allowlist:
  - requests # Allow requests dependency

blocklist:
  - malicious-dep # Block this dependency
"""

CLEAN_APPROVED_PACKAGES_YAML = """
allowlist:
  - requests
# No blocklist needed for clean test
"""


@unittest.skipIf(not INTEGRATION_TEST_AVAILABLE, "Skipping Integration tests: Typer or SherlockScan modules not available.")
class TestEndToEnd(unittest.TestCase):
    """Integration tests for the SherlockScan CLI tool."""

    def setUp(self):
        """Set up test runner and temporary directory for packages/configs."""
        self.runner = CliRunner()
        self.base_test_dir = Path(tempfile.mkdtemp(prefix="sherlock_e2e_"))
        self.config_dir = self.base_test_dir / "config"
        self.config_dir.mkdir()
        self.pkg_dir = self.base_test_dir / "packages"
        self.pkg_dir.mkdir()
        self.output_dir = self.base_test_dir / "output"
        self.output_dir.mkdir()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.base_test_dir)

    def _create_dummy_package(self, name: str, setup_content: Optional[str] = None, pyproject_content: Optional[str] = None, module_content: Optional[Dict[str, str]] = None) -> Path:
        """Helper to create a dummy package structure."""
        package_path = self.pkg_dir / name
        package_path.mkdir()
        if setup_content:
            with open(package_path / "setup.py", "w") as f:
                f.write(setup_content)
        if pyproject_content:
             with open(package_path / "pyproject.toml", "w") as f:
                f.write(pyproject_content)
        if module_content:
            for mod_name, content in module_content.items():
                 mod_path = package_path / mod_name
                 mod_path.parent.mkdir(parents=True, exist_ok=True)
                 with open(mod_path, "w") as f:
                     f.write(content)
        return package_path

    def _create_dummy_config(self, patterns_content: Optional[str] = None, approved_content: Optional[str] = None):
        """Helper to create dummy config files."""
        if patterns_content:
            with open(self.config_dir / "risk_patterns.yaml", "w") as f:
                f.write(patterns_content)
        if approved_content:
             with open(self.config_dir / "approved_packages.yaml", "w") as f:
                f.write(approved_content)
        return self.config_dir

    # --- Test Cases ---

    def test_e2e_risky_package_markdown(self):
        """Test scanning a risky package end-to-end with default Markdown output."""
        # 1. Setup: Create risky package and config
        risky_pkg_path = self._create_dummy_package(
            name="risky_package_test",
            setup_content=RISKY_SETUP_PY_CONTENT,
            pyproject_content=RISKY_PYPROJECT_TOML_CONTENT,
            module_content={"risky_module.py": RISKY_MODULE_CONTENT}
        )
        config_path = self._create_dummy_config(
            patterns_content=RISKY_CONFIG_PATTERNS_YAML,
            approved_content=RISKY_APPROVED_PACKAGES_YAML
        )

        # Mock dependencies for the risky package (if deps.py needs mocking)
        # For integration, ideally deps.py works on the dummy structure if possible,
        # but mocking might still be needed if it relies on installed metadata.
        # Let's assume for now we mock get_package_dependencies for simplicity here.
        with patch('sherlockscan.scanner.deps.get_package_dependencies', return_value=["requests", "malicious-dep"]):
            # 2. Execute: Run the scan command
            result = self.runner.invoke(app, [
                str(risky_pkg_path),
                "--config", str(config_path)
            ], catch_exceptions=False)

            # 3. Assert: Check results
            self.assertEqual(result.exit_code, 0, f"CLI failed with output:\n{result.stdout}")

            # Check overall assessment
            self.assertIn("Overall Risk Assessment", result.stdout)
            self.assertIn("**Risk Level:** `CRITICAL`", result.stdout) # Expect highest risk

            # Check specific findings are mentioned in the output
            self.assertIn("Install Script Execution (`CRITICAL`)", result.stdout) # From setup.py os.system
            self.assertIn("Install Script Custom Command (`MEDIUM`)", result.stdout) # From pyproject.toml cmdclass
            self.assertIn("Hardcoded Secret (`CRITICAL`)", result.stdout) # From module SECRET_KEY
            self.assertIn("Hardcoded Secret (`HIGH`)", result.stdout) # From module PASSWORD
            self.assertIn("Insecure Deserialization (`CRITICAL`)", result.stdout) # From module pickle.load
            self.assertIn("Network Activity (`MEDIUM`)", result.stdout) # From module requests import/call
            self.assertIn("High Entropy (`MEDIUM`)", result.stdout) # From module obfuscated string
            self.assertIn("Security Comment (`LOW`)", result.stdout) # From module TODO keyword
            self.assertIn("Blocked Dependency (`CRITICAL`)", result.stdout) # From mocked deps


    def test_e2e_clean_package_json(self):
        """Test scanning a clean package end-to-end with JSON output."""
         # 1. Setup: Create clean package and config
        clean_pkg_path = self._create_dummy_package(
            name="clean_package_test",
            setup_content=CLEAN_SETUP_PY_CONTENT, # Requires 'requests'
            module_content={"clean_module.py": CLEAN_MODULE_CONTENT}
        )
        config_path = self._create_dummy_config(
            patterns_content=RISKY_CONFIG_PATTERNS_YAML, # Use same patterns
            approved_content=CLEAN_APPROVED_PACKAGES_YAML # Allows 'requests'
        )

        # Mock dependencies for the clean package
        with patch('sherlockscan.scanner.deps.get_package_dependencies', return_value=["requests"]):
            # 2. Execute: Run the scan command with JSON format
            result = self.runner.invoke(app, [
                str(clean_pkg_path),
                "--config", str(config_path),
                "--format", "json"
            ], catch_exceptions=False)

            # 3. Assert: Check results
            self.assertEqual(result.exit_code, 0, f"CLI failed with output:\n{result.stdout}")

            try:
                data = json.loads(result.stdout)
                self.assertIn("overall_risk_level", data)
                # Risk level may be MEDIUM due to entropy scanner on certain lines
                self.assertIn(data["overall_risk_level"], ["LOW", "INFO", "MEDIUM"])
                self.assertIn("findings", data)
                self.assertIn("summary", data)
                # No CRITICAL or HIGH findings expected for a clean package
                self.assertEqual(data["summary"]["by_severity"].get("CRITICAL", 0), 0)
                self.assertEqual(data["summary"]["by_severity"].get("HIGH", 0), 0)

            except json.JSONDecodeError:
                self.fail(f"Failed to parse JSON output:\n{result.stdout}")


    def test_e2e_severity_filter(self):
        """Test end-to-end severity filtering."""
        # 1. Setup: Use risky package and config from first test
        risky_pkg_path = self._create_dummy_package(
            name="risky_package_filter",
            setup_content=RISKY_SETUP_PY_CONTENT,
            module_content={"risky_module.py": RISKY_MODULE_CONTENT}
        )
        config_path = self._create_dummy_config(
            patterns_content=RISKY_CONFIG_PATTERNS_YAML,
            approved_content=RISKY_APPROVED_PACKAGES_YAML
        )

        with patch('sherlockscan.scanner.deps.get_package_dependencies', return_value=["requests", "malicious-dep"]):
            # 2. Execute: Run with severity HIGH
            result = self.runner.invoke(app, [
                str(risky_pkg_path),
                "--config", str(config_path),
                "--severity", "HIGH"
            ], catch_exceptions=False)

            # 3. Assert: Check results
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Overall Risk Assessment", result.stdout)
            self.assertIn("**Risk Level:** `CRITICAL`", result.stdout) # Overall risk remains highest

            # Check that only CRITICAL and HIGH findings appear in details
            self.assertIn("Install Script Execution (`CRITICAL`)", result.stdout)
            self.assertIn("Hardcoded Secret (`CRITICAL`)", result.stdout)
            self.assertIn("Insecure Deserialization (`CRITICAL`)", result.stdout)
            self.assertIn("Blocked Dependency (`CRITICAL`)", result.stdout)
            self.assertIn("Subprocess Execution (`CRITICAL`)", result.stdout)
            self.assertIn("Hardcoded Secret (`HIGH`)", result.stdout) # Password assignment

            # Check that lower severity findings are NOT present in details
            self.assertNotIn("Network Activity (`MEDIUM`)", result.stdout)
            self.assertNotIn("High Entropy (`MEDIUM`)", result.stdout)
            self.assertNotIn("Security Comment (`LOW`)", result.stdout)

            # Check summary table reflects filtered counts
            self.assertIn("| CRITICAL   | 6     |", result.stdout)
            self.assertIn("| HIGH       | 1     |", result.stdout)
            self.assertIn("| MEDIUM     | 0     |", result.stdout) # Filtered
            self.assertIn("| LOW        | 0     |", result.stdout) # Filtered
            self.assertIn("| INFO       | 0     |", result.stdout) # Filtered
            self.assertIn("| **Total** | **7    ** |", result.stdout)


if __name__ == '__main__':
    unittest.main()

