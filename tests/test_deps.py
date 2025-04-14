#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/test_deps.py

import unittest
import tempfile
import os
import logging
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from unittest.mock import patch, MagicMock

# Assume sherlockscan is installed or PYTHONPATH is set correctly
# Need to handle potential import errors for dependencies if testing standalone
try:
    from sherlockscan.scanner.deps import (
        scan_dependencies,
        load_approved_packages,
        get_package_dependencies, # We will mock this
        parse_requirement
    )
    # Also need canonicalize_name if testing load_approved_packages directly
    from packaging.utils import canonicalize_name 
    PACKAGING_AVAILABLE = True
except ImportError:
    # Fallback if packaging is not available, tests relying on it will be skipped or fail
    PACKAGING_AVAILABLE = False
    canonicalize_name = lambda x: x.lower().replace('_', '-') # Basic mock

# Disable logging during tests unless debugging
logging.disable(logging.CRITICAL)

# Sample Config Content for testing
SAMPLE_APPROVED_PKGS_CONTENT = """
allowlist:
  - requests
  - numpy # Canonical: numpy
  - scikit_learn # Canonical: scikit-learn

blocklist:
  - malicious-lib # Canonical: malicious-lib
  - Bad_Package # Canonical: bad-package
"""

class TestDependencyScanner(unittest.TestCase):
    """Unit tests for the deps scanner module."""

    def _create_temp_config(self, content: str) -> Path:
        """Helper to create a temporary YAML config file."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=".yaml", delete=False, encoding='utf-8')
        temp_file.write(content)
        temp_file.close()
        return Path(temp_file.name)

    def _assert_finding_present(self, findings: List[Dict[str, Any]], expected_type: str, expected_severity: str, expected_dep_name: str):
        """Helper to assert if a specific dependency finding is present."""
        found = False
        matching_finding = None
        # Canonicalize expected name for comparison
        canonical_expected_name = canonicalize_name(expected_dep_name) if PACKAGING_AVAILABLE else expected_dep_name.lower().replace('_','-')
        
        for finding in findings:
            type_match = finding.get("type") == expected_type
            severity_match = finding.get("severity") == expected_severity
            # Check if the canonical name is in the code snippet or message
            detail_match = False
            snippet = finding.get("code_snippet", "")
            # Basic check: see if canonical name appears after "Dependency: " in snippet
            if snippet.startswith("Dependency: "):
                 found_dep_name_in_snippet = snippet.split(" ")[1]
                 # Canonicalize the name found in the snippet before comparing
                 canonical_found_name = canonicalize_name(found_dep_name_in_snippet) if PACKAGING_AVAILABLE else found_dep_name_in_snippet.lower().replace('_','-')
                 if canonical_found_name == canonical_expected_name:
                     detail_match = True

            if type_match and severity_match and detail_match:
                 found = True
                 matching_finding = finding
                 break
                     
        assertion_msg = f"Expected finding type='{expected_type}', severity='{expected_severity}' for dependency '{canonical_expected_name}' not found."
        self.assertTrue(found, assertion_msg)
        return matching_finding

    # --- Test Config Loading ---
    @unittest.skipIf(not PACKAGING_AVAILABLE, "Skipping test: 'packaging' library not available")
    def test_load_approved_packages_valid(self):
        """Test loading a valid approved_packages.yaml file."""
        temp_config_path = self._create_temp_config(SAMPLE_APPROVED_PKGS_CONTENT)
        try:
            config = load_approved_packages(str(temp_config_path))
            self.assertIn("allowlist", config)
            self.assertIn("blocklist", config)
            self.assertEqual(config["allowlist"], {"requests", "numpy", "scikit-learn"})
            self.assertEqual(config["blocklist"], {"malicious-lib", "bad-package"})
        finally:
            os.remove(temp_config_path)

    def test_load_approved_packages_missing_file(self):
        """Test loading when the approved_packages file doesn't exist."""
        config = load_approved_packages("non_existent_approved_pkgs.yaml")
        self.assertEqual(config["allowlist"], set())
        self.assertEqual(config["blocklist"], set())

    # --- Test Requirement Parsing ---
    @unittest.skipIf(not PACKAGING_AVAILABLE, "Skipping test: 'packaging' library not available")
    def test_parse_requirement_valid(self):
        """Test parsing various valid requirement strings."""
        self.assertEqual(parse_requirement("requests"), "requests")
        self.assertEqual(parse_requirement("numpy>=1.20"), "numpy")
        self.assertEqual(parse_requirement("scikit_learn"), "scikit-learn") # Canonicalization
        self.assertEqual(parse_requirement("package[extra]"), "package")
        self.assertEqual(parse_requirement("  whitespace_test  "), "whitespace-test")

    def test_parse_requirement_invalid(self):
        """Test parsing invalid requirement strings."""
        # Should return None or a best guess depending on fallback logic
        # Current fallback is basic regex, might return something or None
        logging.disable(logging.WARNING) # Suppress expected warnings
        self.assertIsNotNone(parse_requirement("invalid requirement string")) # Fallback might grab 'invalid'
        self.assertIsNone(parse_requirement(">=1.0")) # No package name
        logging.disable(logging.CRITICAL) # Re-enable default

    # --- Test Dependency Scanning Logic ---
    # We use mocking heavily here to avoid depending on the actual environment

    @patch('sherlockscan.scanner.deps.get_package_dependencies')
    def test_blocked_dependency(self, mock_get_deps):
        """Test detection of a blocked dependency."""
        mock_get_deps.return_value = ["requests>=2.0", "malicious-lib==1.1"] # Mock dependencies
        temp_config_path = self._create_temp_config(SAMPLE_APPROVED_PKGS_CONTENT)
        try:
            findings = scan_dependencies("my-package", str(temp_config_path))
            self.assertEqual(len(findings), 1)
            self._assert_finding_present(findings, "Blocked Dependency", "CRITICAL", "malicious-lib")
        finally:
            os.remove(temp_config_path)

    @patch('sherlockscan.scanner.deps.get_package_dependencies')
    def test_unapproved_dependency_with_allowlist(self, mock_get_deps):
        """Test detection of an unapproved dependency when allowlist is enforced."""
        mock_get_deps.return_value = ["requests", "numpy", "unknown-third-party"] # Mock dependencies
        temp_config_path = self._create_temp_config(SAMPLE_APPROVED_PKGS_CONTENT)
        try:
            findings = scan_dependencies("my-package", str(temp_config_path))
            # Should find 1 unapproved dep, requests & numpy are allowed
            self.assertEqual(len(findings), 1)
            self._assert_finding_present(findings, "Unapproved Dependency", "MEDIUM", "unknown-third-party")
        finally:
            os.remove(temp_config_path)

    @patch('sherlockscan.scanner.deps.get_package_dependencies')
    def test_all_allowed_dependency_with_allowlist(self, mock_get_deps):
        """Test when all dependencies are in the allowlist."""
        mock_get_deps.return_value = ["requests", "numpy", "scikit_learn"] # Mock dependencies
        temp_config_path = self._create_temp_config(SAMPLE_APPROVED_PKGS_CONTENT)
        try:
            findings = scan_dependencies("my-package", str(temp_config_path))
            self.assertEqual(len(findings), 0) # No findings expected
        finally:
            os.remove(temp_config_path)

    @patch('sherlockscan.scanner.deps.get_package_dependencies')
    def test_no_allowlist_defined(self, mock_get_deps):
        """Test behavior when no allowlist is defined (only blocklist matters)."""
        config_content = """
blocklist:
  - malicious-lib
# allowlist is missing/empty
"""
        mock_get_deps.return_value = ["requests", "numpy", "unknown-third-party", "malicious-lib"]
        temp_config_path = self._create_temp_config(config_content)
        try:
            findings = scan_dependencies("my-package", str(temp_config_path))
            # Should only find the blocked dependency
            self.assertEqual(len(findings), 1)
            self._assert_finding_present(findings, "Blocked Dependency", "CRITICAL", "malicious-lib")
        finally:
            os.remove(temp_config_path)

    @patch('sherlockscan.scanner.deps.get_package_dependencies')
    def test_blocked_and_unapproved(self, mock_get_deps):
        """Test when both blocked and unapproved dependencies are present."""
        mock_get_deps.return_value = ["requests", "malicious-lib", "unknown-third-party", "Bad_Package"]
        temp_config_path = self._create_temp_config(SAMPLE_APPROVED_PKGS_CONTENT)
        try:
            findings = scan_dependencies("my-package", str(temp_config_path))
            # Expect 2 blocked, 1 unapproved
            self.assertEqual(len(findings), 3)
            self._assert_finding_present(findings, "Blocked Dependency", "CRITICAL", "malicious-lib")
            self._assert_finding_present(findings, "Blocked Dependency", "CRITICAL", "Bad_Package")
            self._assert_finding_present(findings, "Unapproved Dependency", "MEDIUM", "unknown-third-party")
        finally:
            os.remove(temp_config_path)

    @patch('sherlockscan.scanner.deps.get_package_dependencies')
    def test_package_not_found(self, mock_get_deps):
        """Test behavior when the target package's dependencies cannot be retrieved."""
        mock_get_deps.return_value = None # Simulate package not found by helper
        temp_config_path = self._create_temp_config(SAMPLE_APPROVED_PKGS_CONTENT)
        try:
            findings = scan_dependencies("non-existent-package", str(temp_config_path))
            self.assertEqual(len(findings), 0) # No findings expected
        finally:
            os.remove(temp_config_path)


if __name__ == '__main__':
    unittest.main()

