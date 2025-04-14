#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/test_heuristics.py

import unittest
import tempfile
import os
import logging
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional

# Assume sherlockscan is installed or PYTHONPATH is set correctly
from sherlockscan.scanner.heuristics import scan_file_heuristics, load_risk_patterns, calculate_entropy, DEFAULT_ENTROPY_THRESHOLD

# Disable logging during tests unless debugging
logging.disable(logging.CRITICAL)

# Sample Config Content for testing
SAMPLE_CONFIG_CONTENT = """
settings:
  entropy_threshold: 4.5 # Use a specific threshold for tests

regex_patterns:
  - name: Test API Key
    type: Hardcoded Secret
    pattern: 'test_key_[a-f0-9]{10}' # Example pattern
    severity: HIGH
    message: "Test API Key detected."
  - name: Simple Password Assignment
    type: Hardcoded Secret
    pattern: 'password\s*=\s*["\'](.*?)["\']'
    severity: CRITICAL
    message: "Password assignment found: {match}" # Test message formatting

keywords:
  - name: TODO Security Keyword
    type: Security Comment
    keyword: "TODO: security" # Scanner converts line to lower
    severity: LOW
    message: "Security TODO found."
  - name: Secret Keyword
    type: Suspicious Keyword
    keyword: "SECRET" # Scanner converts line to lower
    severity: MEDIUM
    message: "Keyword {keyword} found."
"""

INVALID_YAML_CONTENT = """
regex_patterns:
  - name: Bad Indent
   pattern: 'bad'
"""

class TestHeuristicsScanner(unittest.TestCase):
    """Unit tests for the heuristics scanner module."""

    def _create_temp_file(self, content: str, suffix=".py") -> Path:
        """Helper to create a temporary file."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False, encoding='utf-8')
        temp_file.write(content)
        temp_file.close()
        return Path(temp_file.name)

    def _create_temp_config(self, content: str) -> Path:
        """Helper to create a temporary YAML config file."""
        return self._create_temp_file(content, suffix=".yaml")

    def _assert_finding_present(self, findings: List[Dict[str, Any]], expected_type: str, expected_severity: str, expected_line: Optional[int] = None, expected_message_part: Optional[str] = None):
        """Helper to assert if a specific type of finding is present."""
        found = False
        matching_finding = None
        for finding in findings:
            line_match = (expected_line is None or finding.get("line_number") == expected_line)
            type_match = finding.get("type") == expected_type
            severity_match = finding.get("severity") == expected_severity
            
            if type_match and severity_match and line_match:
                 # If message part is provided, check if it's in the finding message
                 if expected_message_part:
                     if expected_message_part in finding.get("message", ""):
                         found = True
                         matching_finding = finding
                         break
                 else:
                     found = True
                     matching_finding = finding
                     break
                     
        assertion_msg = f"Expected finding type='{expected_type}', severity='{expected_severity}'"
        if expected_line: assertion_msg += f" on line {expected_line}"
        if expected_message_part: assertion_msg += f" with message containing '{expected_message_part}'"
        assertion_msg += " not found."
        
        self.assertTrue(found, assertion_msg)
        return matching_finding # Return the found finding for further checks if needed

    # --- Test Config Loading ---
    def test_load_risk_patterns_valid(self):
        """Test loading a valid configuration file."""
        temp_config_path = self._create_temp_config(SAMPLE_CONFIG_CONTENT)
        try:
            patterns = load_risk_patterns(str(temp_config_path))
            self.assertIn("regex_patterns", patterns)
            self.assertIn("keywords", patterns)
            self.assertIn("settings", patterns)
            self.assertEqual(len(patterns["regex_patterns"]), 2)
            self.assertEqual(len(patterns["keywords"]), 2)
            self.assertEqual(patterns["settings"]["entropy_threshold"], 4.5)
        finally:
            os.remove(temp_config_path)

    def test_load_risk_patterns_missing_file(self):
        """Test loading when the config file doesn't exist."""
        patterns = load_risk_patterns("non_existent_config.yaml")
        self.assertEqual(patterns["regex_patterns"], [])
        self.assertEqual(patterns["keywords"], [])
        self.assertEqual(patterns["settings"]["entropy_threshold"], DEFAULT_ENTROPY_THRESHOLD)

    def test_load_risk_patterns_invalid_yaml(self):
        """Test loading an invalid YAML file."""
        temp_config_path = self._create_temp_config(INVALID_YAML_CONTENT)
        try:
            # Suppress expected ERROR log during this test
            logging.disable(logging.ERROR)
            patterns = load_risk_patterns(str(temp_config_path))
            logging.disable(logging.CRITICAL) # Re-enable default suppression
            self.assertEqual(patterns["regex_patterns"], [])
            self.assertEqual(patterns["keywords"], [])
            self.assertEqual(patterns["settings"]["entropy_threshold"], DEFAULT_ENTROPY_THRESHOLD)
        finally:
            os.remove(temp_config_path)

    # --- Test Scanners ---
    def test_regex_detection(self):
        """Test detection using regex patterns."""
        code = """
api_key = "test_key_abcdef0123" # Line 2
password = "mypassword123"     # Line 3
other_var = "no_key_here"
"""
        temp_config_path = self._create_temp_config(SAMPLE_CONFIG_CONTENT)
        temp_code_path = self._create_temp_file(code)
        try:
            findings = scan_file_heuristics(str(temp_code_path), str(temp_config_path))
            self.assertEqual(len(findings), 2)
            self._assert_finding_present(findings, "Hardcoded Secret", "HIGH", 2, "Test API Key")
            finding_pass = self._assert_finding_present(findings, "Hardcoded Secret", "CRITICAL", 3, "Password assignment")
            # Check message formatting
            self.assertIn('match=password = "mypassword123"', finding_pass['message'])
        finally:
            os.remove(temp_config_path)
            os.remove(temp_code_path)

    def test_keyword_detection(self):
        """Test detection using keywords."""
        code = """
# TODO: security review needed here  # Line 2
# This line contains the SECRET keyword # Line 3
normal_code = 1
"""
        temp_config_path = self._create_temp_config(SAMPLE_CONFIG_CONTENT)
        temp_code_path = self._create_temp_file(code)
        try:
            findings = scan_file_heuristics(str(temp_code_path), str(temp_config_path))
            self.assertEqual(len(findings), 2)
            self._assert_finding_present(findings, "Security Comment", "LOW", 2, "Security TODO")
            self._assert_finding_present(findings, "Suspicious Keyword", "MEDIUM", 3, "Keyword SECRET")
        finally:
            os.remove(temp_config_path)
            os.remove(temp_code_path)

    def test_entropy_detection(self):
        """Test detection using entropy calculation."""
        # EICAR string has high entropy
        high_entropy_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        low_entropy_string = "this is a normal sentence with low entropy"
        code = f"""
variable_normal = "{low_entropy_string}" # Line 2
variable_obfuscated = "{high_entropy_string}" # Line 3
"""
        temp_config_path = self._create_temp_config(SAMPLE_CONFIG_CONTENT) # Uses threshold 4.5
        temp_code_path = self._create_temp_file(code)
        try:
            # Verify entropy calculation helper
            self.assertLess(calculate_entropy(low_entropy_string), 4.5)
            self.assertGreater(calculate_entropy(high_entropy_string), 4.5)

            findings = scan_file_heuristics(str(temp_code_path), str(temp_config_path))
            self.assertEqual(len(findings), 1)
            self._assert_finding_present(findings, "High Entropy", "MEDIUM", 3)
        finally:
            os.remove(temp_config_path)
            os.remove(temp_code_path)

    def test_combined_detection(self):
        """Test detecting multiple types of findings in one file."""
        high_entropy_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        code = f"""
key = "test_key_12345abcde" # Line 2 (Regex)
# TODO: security check this key # Line 3 (Keyword)
obfuscated = "{high_entropy_string}" # Line 4 (Entropy)
"""
        temp_config_path = self._create_temp_config(SAMPLE_CONFIG_CONTENT)
        temp_code_path = self._create_temp_file(code)
        try:
            findings = scan_file_heuristics(str(temp_code_path), str(temp_config_path))
            self.assertEqual(len(findings), 3)
            self._assert_finding_present(findings, "Hardcoded Secret", "HIGH", 2)
            self._assert_finding_present(findings, "Security Comment", "LOW", 3)
            self._assert_finding_present(findings, "High Entropy", "MEDIUM", 4)
        finally:
            os.remove(temp_config_path)
            os.remove(temp_code_path)

    def test_clean_file(self):
        """Test scanning a file with no patterns matching the config."""
        code = """
import math
# This is a safe file
variable = "normal string"
result = math.sqrt(16)
"""
        temp_config_path = self._create_temp_config(SAMPLE_CONFIG_CONTENT)
        temp_code_path = self._create_temp_file(code)
        try:
            findings = scan_file_heuristics(str(temp_code_path), str(temp_config_path))
            self.assertEqual(len(findings), 0)
        finally:
            os.remove(temp_config_path)
            os.remove(temp_code_path)

    def test_file_not_found(self):
        """Test scanning a non-existent code file."""
        temp_config_path = self._create_temp_config(SAMPLE_CONFIG_CONTENT)
        try:
            # Suppress expected ERROR log during this test
            logging.disable(logging.ERROR)
            findings = scan_file_heuristics("non_existent_code_file.py", str(temp_config_path))
            logging.disable(logging.CRITICAL) # Re-enable default suppression
            self.assertEqual(len(findings), 0)
        finally:
            os.remove(temp_config_path)

    def test_missing_config_file(self):
        """Test scanning when the config file is missing."""
        code = """key = "test_key_12345abcde" """
        temp_code_path = self._create_temp_file(code)
        try:
            # Suppress expected WARNING log during this test
            logging.disable(logging.WARNING)
            findings = scan_file_heuristics(str(temp_code_path), "non_existent_config.yaml")
            logging.disable(logging.CRITICAL) # Re-enable default suppression
            # Expect no findings as no patterns were loaded
            self.assertEqual(len(findings), 0)
        finally:
            os.remove(temp_code_path)


if __name__ == '__main__':
    unittest.main()

