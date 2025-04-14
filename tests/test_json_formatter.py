#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/test_json_formatter.py

import unittest
import json
import logging
import datetime
from typing import List, Dict, Any, Optional

# Assume sherlockscan is installed or PYTHONPATH is set correctly
from sherlockscan.report.json_formatter import format_report_json

# Disable logging during tests
logging.disable(logging.CRITICAL)

class TestJsonFormatter(unittest.TestCase):
    """Unit tests for the json_formatter module."""

    def setUp(self):
        """Set up sample data used across multiple tests."""
        self.sample_package_name = "test-pkg"
        self.sample_package_version = "1.2.3"
        self.sample_findings = [
            {"type": "Hardcoded Secret", "severity": "CRITICAL", "file_path": "a.py", "line_number": 10, "message": "Secret found", "code_snippet": "key = ..."},
            {"type": "Risky Call", "severity": "HIGH", "file_path": "b/c.py", "line_number": 25, "message": "Eval used", "code_snippet": "eval(...)"},
        ]
        self.sample_summary = {"total_findings": 2, "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
        self.sample_risk_level = "CRITICAL"
        self.sample_explanation = "Critical issues found: Package contains hardcoded secrets. Recommend audit."

    def test_basic_formatting(self):
        """Test the basic structure and content of the formatted JSON."""
        json_string = format_report_json(
            package_name=self.sample_package_name,
            package_version=self.sample_package_version,
            findings=self.sample_findings,
            summary=self.sample_summary,
            overall_risk_level=self.sample_risk_level,
            explanation=self.sample_explanation
        )
        
        # Check if it's valid JSON
        try:
            data = json.loads(json_string)
        except json.JSONDecodeError as e:
            self.fail(f"Output is not valid JSON: {e}\nOutput:\n{json_string}")

        # Check top-level keys
        self.assertIn("package_name", data)
        self.assertIn("package_version", data)
        self.assertIn("scan_timestamp", data)
        self.assertIn("overall_risk_level", data)
        self.assertIn("findings", data)
        self.assertIn("summary", data)
        self.assertIn("explanation", data)

        # Check specific values
        self.assertEqual(data["package_name"], self.sample_package_name)
        self.assertEqual(data["package_version"], self.sample_package_version)
        self.assertEqual(data["overall_risk_level"], self.sample_risk_level)
        self.assertEqual(data["explanation"], self.sample_explanation)
        
        # Check complex types
        self.assertIsInstance(data["findings"], list)
        self.assertEqual(len(data["findings"]), len(self.sample_findings))
        self.assertDictEqual(data["findings"][0], self.sample_findings[0]) # Check first finding details
        
        self.assertIsInstance(data["summary"], dict)
        self.assertDictEqual(data["summary"], self.sample_summary)

        # Check timestamp format (basic ISO 8601 UTC check)
        self.assertIsInstance(data["scan_timestamp"], str)
        self.assertTrue(data["scan_timestamp"].endswith("Z"))
        try:
            # Attempt to parse timestamp to ensure validity
            datetime.datetime.strptime(data["scan_timestamp"], '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            self.fail("scan_timestamp is not in expected ISO 8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)")

    def test_null_version(self):
        """Test formatting when package_version is None."""
        json_string = format_report_json(
            package_name=self.sample_package_name,
            package_version=None, # Test None version
            findings=self.sample_findings,
            summary=self.sample_summary,
            overall_risk_level=self.sample_risk_level,
            explanation=self.sample_explanation
        )
        data = json.loads(json_string)
        self.assertIn("package_version", data)
        self.assertIsNone(data["package_version"]) # Should be JSON null

    def test_empty_findings(self):
        """Test formatting when the findings list is empty."""
        empty_findings: List[Dict[str, Any]] = []
        empty_summary = {"total_findings": 0, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
        low_risk_level = "LOW"
        low_explanation = "No findings."
        
        json_string = format_report_json(
            package_name=self.sample_package_name,
            package_version=self.sample_package_version,
            findings=empty_findings,
            summary=empty_summary,
            overall_risk_level=low_risk_level,
            explanation=low_explanation
        )
        data = json.loads(json_string)
        self.assertIn("findings", data)
        self.assertIsInstance(data["findings"], list)
        self.assertEqual(len(data["findings"]), 0)
        self.assertDictEqual(data["summary"], empty_summary)
        self.assertEqual(data["overall_risk_level"], low_risk_level)

    def test_serialization_error(self):
        """Test the fallback behavior when JSON serialization fails."""
        # Create data that cannot be serialized directly to JSON
        invalid_findings = [{"unserializable": datetime.datetime.now()}]
        
        # Suppress expected ERROR log during this test
        logging.disable(logging.ERROR)
        json_string = format_report_json(
            package_name=self.sample_package_name,
            package_version=self.sample_package_version,
            findings=invalid_findings, # type: ignore
            summary=self.sample_summary,
            overall_risk_level=self.sample_risk_level,
            explanation=self.sample_explanation
        )
        logging.disable(logging.CRITICAL) # Re-enable default suppression

        # Expect an empty JSON object string as fallback
        self.assertEqual(json_string, "{}")


if __name__ == '__main__':
    unittest.main()

