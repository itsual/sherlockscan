#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/test_cli.py

import unittest
import tempfile
import os
import json
import logging
import shutil
from pathlib import Path
from typing import List
from unittest.mock import patch, MagicMock, ANY # ANY helps check calls without matching complex args

# Import the Typer app instance from cli.py
# Need to handle potential import errors if modules are not found
try:
    from typer.testing import CliRunner
    from sherlockscan.cli import app # The Typer app instance
    from sherlockscan.exceptions import PackageNotFoundError
    TYPER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import Typer or SherlockScan modules for CLI tests: {e}")
    print("CLI tests will be skipped.")
    TYPER_AVAILABLE = False
    # Define dummy classes/vars if needed to allow file parsing
    class CliRunner: pass
    app = None

# Disable logging during tests unless debugging
logging.disable(logging.CRITICAL)

# Sample finding data for mocking scanner returns
MOCK_FINDING_CRITICAL = {"type": "Hardcoded Secret", "severity": "CRITICAL", "file_path": "a.py", "line_number": 1, "message": "Crit", "code_snippet": "..."}
MOCK_FINDING_HIGH = {"type": "Risky Call", "severity": "HIGH", "file_path": "a.py", "line_number": 2, "message": "High", "code_snippet": "..."}
MOCK_FINDING_MEDIUM = {"type": "Network Activity", "severity": "MEDIUM", "file_path": "b.py", "line_number": 3, "message": "Med", "code_snippet": "..."}
MOCK_FINDING_LOW = {"type": "Keyword Match", "severity": "LOW", "file_path": "b.py", "line_number": 4, "message": "Low", "code_snippet": "..."}
MOCK_FINDINGS_ALL = [MOCK_FINDING_CRITICAL, MOCK_FINDING_HIGH, MOCK_FINDING_MEDIUM, MOCK_FINDING_LOW]

# Expected return from mocked resolve_package_target
MOCK_PKG_NAME = "dummy-package"
MOCK_PKG_VERSION = "1.0.0"
MOCK_PKG_PATH = Path("./dummy_pkg_src") # Needs to exist temporarily during test


@unittest.skipIf(not TYPER_AVAILABLE, "Skipping CLI tests: Typer or SherlockScan modules not available.")
class TestCli(unittest.TestCase):
    """Unit tests for the cli.py module using Typer's test runner."""

    def setUp(self):
        """Set up test runner and temporary directory."""
        self.runner = CliRunner()
        self.test_dir = Path(tempfile.mkdtemp(prefix="sherlock_cli_test_"))
        # Create mock package source dir needed by mocked resolve_package_target
        (self.test_dir / MOCK_PKG_PATH).mkdir(exist_ok=True)

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)

    # --- Mock Setup ---
    # Use decorators to patch functions called by cli.scan
    # Patch targets should be where they are *looked up*, which is often where they are imported/used.
    @patch('sherlockscan.cli._get_package_path_and_info') # Mock helper within cli.py
    @patch('sherlockscan.cli._find_python_files') # Mock helper within cli.py
    @patch('sherlockscan.cli.install_script_analyzer.scan_install_scripts')
    @patch('sherlockscan.cli.deps.scan_dependencies')
    @patch('sherlockscan.cli.ast_scanner.scan_file_ast')
    @patch('sherlockscan.cli.heuristics.scan_file_heuristics')
    @patch('sherlockscan.cli.explainer.generate_overall_explanation')
    def run_scan_command(
        self,
        cli_args: List[str],
        mock_explainer: MagicMock,
        mock_heuristics: MagicMock,
        mock_ast: MagicMock,
        mock_deps: MagicMock,
        mock_install: MagicMock,
        mock_find_py: MagicMock,
        mock_resolve_pkg: MagicMock,
        # --- Mock Configuration ---
        resolve_pkg_return = (MOCK_PKG_PATH, MOCK_PKG_NAME, MOCK_PKG_VERSION),
        find_py_return = [MOCK_PKG_PATH / "file1.py", MOCK_PKG_PATH / "file2.py"],
        install_findings = [],
        deps_findings = [],
        ast_findings = [],
        heuristics_findings = [],
        explanation = "Mock explanation."
    ):
        """Helper method to run the CLI scan command with extensive mocking."""
        # Configure mock return values
        mock_resolve_pkg.return_value = resolve_pkg_return
        mock_find_py.return_value = find_py_return
        mock_install.return_value = install_findings
        mock_deps.return_value = deps_findings
        # Make scanners return findings per file - simplified: return all findings for first file call
        mock_ast.side_effect = lambda path: ast_findings if path == str(find_py_return[0]) else []
        mock_heuristics.side_effect = lambda path, cfg: heuristics_findings if path == str(find_py_return[0]) else []
        mock_explainer.return_value = explanation

        # Invoke the CLI command (single-command Typer app, no subcommand name needed)
        result = self.runner.invoke(app, cli_args, catch_exceptions=False)

        # Return result and mocks for assertions
        return result, {
            "resolve_pkg": mock_resolve_pkg, "find_py": mock_find_py,
            "install": mock_install, "deps": mock_deps, "ast": mock_ast,
            "heuristics": mock_heuristics, "explainer": mock_explainer
        }

    # --- Test Cases ---

    def test_scan_markdown_console_defaults(self):
        """Test default scan: markdown output to console."""
        target_pkg = "dummy-package"
        result, mocks = self.run_scan_command(
            [target_pkg],
            ast_findings=[MOCK_FINDING_HIGH],
            deps_findings=[MOCK_FINDING_MEDIUM],
            explanation="High risk found."
        )

        # Check exit code and output
        self.assertEqual(result.exit_code, 0, f"CLI exited with code {result.exit_code}\nOutput:\n{result.stdout}")
        self.assertIn(f"# SherlockScan Report: `{target_pkg}`", result.stdout) # Check MD Title
        self.assertIn("## Overall Risk Assessment", result.stdout)
        self.assertIn("**Risk Level:** `HIGH`", result.stdout) # Risk derived from findings
        self.assertIn("High risk found.", result.stdout) # Mocked explanation
        self.assertIn("## Detailed Findings", result.stdout)
        self.assertIn("### Risky Call (`HIGH`)", result.stdout) # High finding detail
        self.assertIn("### Network Activity (`MEDIUM`)", result.stdout) # Medium finding detail

        # Check mocks were called
        mocks["resolve_pkg"].assert_called_once_with(target_pkg)
        mocks["install"].assert_called_once_with(str(MOCK_PKG_PATH))
        mocks["deps"].assert_called_once_with(MOCK_PKG_NAME, str(Path("./config/approved_packages.yaml"))) # Default config path
        self.assertGreaterEqual(mocks["ast"].call_count, 1)
        self.assertGreaterEqual(mocks["heuristics"].call_count, 1)
        mocks["explainer"].assert_called_once()


    def test_scan_json_output_console(self):
        """Test JSON output to console."""
        target_pkg = "dummy-package"
        result, mocks = self.run_scan_command(
            [target_pkg, "--format", "json"],
            ast_findings=[MOCK_FINDING_CRITICAL],
            explanation="Critical risk."
        )

        self.assertEqual(result.exit_code, 0)
        # Try parsing the output as JSON
        try:
            data = json.loads(result.stdout)
            self.assertEqual(data["package_name"], target_pkg)
            self.assertEqual(data["overall_risk_level"], "CRITICAL")
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(data["findings"][0]["type"], MOCK_FINDING_CRITICAL["type"])
            self.assertEqual(data["explanation"], "Critical risk.")
        except json.JSONDecodeError:
            self.fail(f"Failed to parse JSON output:\n{result.stdout}")

    def test_scan_output_to_file(self):
        """Test writing the report to an output file."""
        target_pkg = "dummy-package"
        output_file = self.test_dir / "report.md"
        result, mocks = self.run_scan_command(
            [target_pkg, "--output", str(output_file)],
            ast_findings=[MOCK_FINDING_LOW],
            explanation="Low risk."
        )

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(output_file.exists(), "Output file was not created.")
        # Stdout should be minimal (only logs, no report)
        self.assertNotIn("# SherlockScan Report", result.stdout)
        # Check file content
        with open(output_file, "r") as f:
            content = f.read()
            self.assertIn(f"# SherlockScan Report: `{target_pkg}`", content)
            self.assertIn("Low risk.", content)
            self.assertIn("Keyword Match (`LOW`)", content) # Check finding detail

    def test_scan_severity_filtering(self):
        """Test filtering findings by minimum severity."""
        target_pkg = "filter-package"
        result, mocks = self.run_scan_command(
            [target_pkg, "--severity", "HIGH"], # Only show HIGH and CRITICAL
            install_findings=[MOCK_FINDING_CRITICAL],
            ast_findings=[MOCK_FINDING_HIGH],
            heuristics_findings=[MOCK_FINDING_MEDIUM], # This should be filtered out
            deps_findings=[MOCK_FINDING_LOW], # This should be filtered out
            explanation="Filtered explanation." # Explainer gets filtered findings
        )

        self.assertEqual(result.exit_code, 0)
        # Check that only Critical and High findings are in the detailed output (assuming MD)
        self.assertIn("Hardcoded Secret (`CRITICAL`)", result.stdout)
        self.assertIn("Risky Call (`HIGH`)", result.stdout)
        self.assertNotIn("Network Activity (`MEDIUM`)", result.stdout)
        self.assertNotIn("Keyword Match (`LOW`)", result.stdout)
        # Check that the summary table reflects the filtered counts
        # (Need more complex check or trust the explainer mock)
        self.assertIn("| CRITICAL   | 1     |", result.stdout)
        self.assertIn("| HIGH       | 1     |", result.stdout)
        self.assertIn("| MEDIUM     | 0     |", result.stdout) # Filtered out
        self.assertIn("| LOW        | 0     |", result.stdout) # Filtered out
        self.assertIn("| **Total** | **2    ** |", result.stdout) # Total reflects filtered count


    def test_scan_custom_config(self):
        """Test using a custom configuration directory."""
        target_pkg = "config-package"
        custom_config_dir = self.test_dir / "custom_cfg"
        custom_config_dir.mkdir()
        # Create dummy config files
        (custom_config_dir / "risk_patterns.yaml").touch()
        (custom_config_dir / "approved_packages.yaml").touch()

        result, mocks = self.run_scan_command(
            [target_pkg, "--config", str(custom_config_dir)],
            deps_findings=[MOCK_FINDING_LOW], # Need some finding to check output
            explanation="Config test."
        )

        self.assertEqual(result.exit_code, 0)
        # Check that scanners were called with the custom config path
        mocks["deps"].assert_called_once_with(MOCK_PKG_NAME, str(custom_config_dir / "approved_packages.yaml"))
        # Heuristics is called per file, check path on one of the calls
        heuristics_call_args = mocks["heuristics"].call_args_list[0] # Get args of first call
        self.assertEqual(heuristics_call_args[0][1], str(custom_config_dir / "risk_patterns.yaml")) # Check config path argument


    def test_scan_package_not_found(self):
        """Test CLI behavior when package resolution fails."""
        target_pkg = "nonexistent-package"
        # Mock _get_package_path_and_info to return None (simulates failure)
        with patch('sherlockscan.cli._get_package_path_and_info', return_value=None):
             result = self.runner.invoke(app, [target_pkg], catch_exceptions=True)
             self.assertNotEqual(result.exit_code, 0, "CLI should exit with non-zero code on package not found.")


    def test_scan_invalid_format(self):
        """Test CLI behavior with an invalid format option."""
        target_pkg = "format-package"
        result, mocks = self.run_scan_command(
            [target_pkg, "--format", "xml"], # Invalid format
        )

        self.assertNotEqual(result.exit_code, 0, "CLI should exit with non-zero code on invalid format.")


if __name__ == '__main__':
    unittest.main()

