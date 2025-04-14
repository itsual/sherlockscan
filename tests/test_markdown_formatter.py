#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/test_markdown_formatter.py

import unittest
import logging
import re # For checking patterns in markdown
from typing import List, Dict, Any, Optional

# Assume sherlockscan is installed or PYTHONPATH is set correctly
from sherlockscan.report.markdown_formatter import format_report_markdown, SEVERITY_ORDER

# Disable logging during tests
logging.disable(logging.CRITICAL)

class TestMarkdownFormatter(unittest.TestCase):
    """Unit tests for the markdown_formatter module."""

    def setUp(self):
        """Set up sample data used across multiple tests."""
        self.sample_package_name = "markdown-pkg"
        self.sample_package_version = "0.9.0"
        # Findings out of order to test sorting
        self.sample_findings = [
             {"type": "Keyword Match", "severity": "LOW", "file_path": "c.py", "line_number": 30, "message": "Low issue", "code_snippet": "# TODO"},
             {"type": "Risky Call", "severity": "HIGH", "file_path": "b/c.py", "line_number": 25, "message": "Eval used", "code_snippet": "eval(...)"},
             {"type": "Hardcoded Secret", "severity": "CRITICAL", "file_path": "a.py", "line_number": 10, "message": "Secret found", "code_snippet": "key = ..."},
             {"type": "Network Activity", "severity": "MEDIUM", "file_path": "d.py", "line_number": 5, "message": "Socket used", "code_snippet": "socket.socket()"},
             {"type": "Install Script Custom Build", "severity": "INFO", "file_path": "pyproject.toml", "line_number": None, "message": "Custom build", "code_snippet": "[build-system]"},
        ]
        self.sample_summary = {"total_findings": 5, "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1}}
        self.sample_risk_level = "CRITICAL"
        self.sample_explanation = "Critical issues found: Package contains hardcoded secrets. High severity issues found: Package uses potentially dangerous functions. Recommend audit."

    def test_basic_structure_and_headers(self):
        """Test the basic Markdown structure and presence of key sections."""
        markdown_string = format_report_markdown(
            package_name=self.sample_package_name,
            package_version=self.sample_package_version,
            findings=self.sample_findings,
            summary=self.sample_summary,
            overall_risk_level=self.sample_risk_level,
            explanation=self.sample_explanation
        )
        
        # Check Title
        self.assertIn(f"# SherlockScan Report: `{self.sample_package_name}`", markdown_string)
        # Check Version
        self.assertIn(f"**Version:** {self.sample_package_version}", markdown_string)
        # Check Separators
        self.assertTrue(markdown_string.count("\n---\n") >= 3)
        # Check Section Headers
        self.assertIn("## Overall Risk Assessment", markdown_string)
        self.assertIn("## Findings Summary", markdown_string)
        self.assertIn("## Detailed Findings", markdown_string)
        # Check Risk Level and Explanation
        self.assertIn(f"**Risk Level:** `{self.sample_risk_level}`", markdown_string)
        self.assertIn(f"\n**Summary:**\n{self.sample_explanation}", markdown_string)

    def test_summary_table_formatting(self):
        """Test the formatting of the summary table."""
        markdown_string = format_report_markdown(
            package_name=self.sample_package_name,
            package_version=self.sample_package_version,
            findings=self.sample_findings,
            summary=self.sample_summary,
            overall_risk_level=self.sample_risk_level,
            explanation=self.sample_explanation
        )
        
        # Check table header
        self.assertIn("| Severity   | Count |", markdown_string)
        self.assertIn("|------------|-------|", markdown_string)
        # Check counts for each severity level present in the sample data
        self.assertIn(f"| CRITICAL   | 1     |", markdown_string)
        self.assertIn(f"| HIGH       | 1     |", markdown_string)
        self.assertIn(f"| MEDIUM     | 1     |", markdown_string)
        self.assertIn(f"| LOW        | 1     |", markdown_string)
        self.assertIn(f"| INFO       | 1     |", markdown_string)
        # Check total
        self.assertIn(f"| **Total** | **{self.sample_summary['total_findings']:<5}** |", markdown_string)

    def test_detailed_findings_formatting_and_sorting(self):
        """Test the formatting and severity sorting of detailed findings."""
        markdown_string = format_report_markdown(
            package_name=self.sample_package_name,
            package_version=self.sample_package_version,
            findings=self.sample_findings, # Findings are intentionally out of order
            summary=self.sample_summary,
            overall_risk_level=self.sample_risk_level,
            explanation=self.sample_explanation
        )
        
        # Find the start of the detailed findings section
        detail_start_index = markdown_string.find("## Detailed Findings")
        self.assertGreater(detail_start_index, -1, "Detailed Findings section not found")
        detail_section = markdown_string[detail_start_index:]

        # Check formatting of a specific finding (e.g., the CRITICAL one)
        self.assertIn("### Hardcoded Secret (`CRITICAL`)", detail_section)
        self.assertIn("- **Location:** `a.py`:10", detail_section)
        self.assertIn("- **Details:** Secret found", detail_section)
        self.assertIn("- **Code Snippet:**\n  ``` python\n  key = ...\n  ```", detail_section)

        # Check formatting of another finding (e.g., INFO with no line number)
        self.assertIn("### Install Script Custom Build (`INFO`)", detail_section)
        self.assertIn("- **Location:** `pyproject.toml`", detail_section) # No line number
        self.assertIn("- **Details:** Custom build", detail_section)
        self.assertIn("- **Code Snippet:**\n  ``` \n  [build-system]\n  ```", detail_section) # No lang hint

        # Check order - Use regex to find severity headers and check their sequence
        severity_headers_found = re.findall(r"### .*?\(`(CRITICAL|HIGH|MEDIUM|LOW|INFO)`\)", detail_section)
        expected_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        self.assertListEqual(severity_headers_found, expected_order, "Findings are not sorted correctly by severity")

    def test_handling_missing_optional_fields(self):
        """Test formatting when optional fields like version, line_number, snippet are missing."""
        findings_missing = [
            {"type": "Type A", "severity": "HIGH", "file_path": "file_a.py", "message": "Msg A"}, # No line, no snippet
            {"type": "Type B", "severity": "MEDIUM", "file_path": "file_b.py", "line_number": 5, "message": "Msg B"}, # No snippet
            {"type": "Type C", "severity": "LOW", "file_path": "file_c.py", "line_number": 15, "message": "Msg C", "code_snippet": None}, # Snippet is None
        ]
        summary_missing = {"total_findings": 3, "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0}}
        risk_missing = "HIGH"
        explanation_missing = "High severity issues found."

        markdown_string = format_report_markdown(
            package_name=self.sample_package_name,
            package_version=None, # Test None version
            findings=findings_missing,
            summary=summary_missing,
            overall_risk_level=risk_missing,
            explanation=explanation_missing
        )

        # Check version is not present
        self.assertNotIn("**Version:**", markdown_string)

        # Check finding A (no line, no snippet)
        self.assertIn("### Type A (`HIGH`)", markdown_string)
        self.assertIn("- **Location:** `file_a.py`", markdown_string) # Only file path
        self.assertNotIn("- **Code Snippet:**", markdown_string) # Snippet section should be absent

        # Check finding B (no snippet)
        self.assertIn("### Type B (`MEDIUM`)", markdown_string)
        self.assertIn("- **Location:** `file_b.py`:5", markdown_string)
        self.assertNotIn("- **Code Snippet:**", markdown_string)

        # Check finding C (snippet is None)
        self.assertIn("### Type C (`LOW`)", markdown_string)
        self.assertIn("- **Location:** `file_c.py`:15", markdown_string)
        self.assertNotIn("- **Code Snippet:**", markdown_string)


    def test_no_findings(self):
        """Test formatting when the findings list is empty."""
        empty_findings: List[Dict[str, Any]] = []
        empty_summary = {"total_findings": 0, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
        low_risk_level = "LOW"
        low_explanation = "No significant risks detected."

        markdown_string = format_report_markdown(
            package_name=self.sample_package_name,
            package_version=self.sample_package_version,
            findings=empty_findings,
            summary=empty_summary,
            overall_risk_level=low_risk_level,
            explanation=low_explanation
        )

        # Check summary table shows zeros
        self.assertIn("| CRITICAL   | 0     |", markdown_string)
        self.assertIn("| HIGH       | 0     |", markdown_string)
        # ... etc ...
        self.assertIn("| **Total** | **0    ** |", markdown_string) # Check total is 0

        # Check detailed findings section indicates none found
        self.assertIn("## Detailed Findings", markdown_string)
        self.assertIn("No findings detected based on current rules.", markdown_string)


if __name__ == '__main__':
    unittest.main()

