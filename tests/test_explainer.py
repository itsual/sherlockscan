#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/test_explainer.py

import unittest
import logging
from typing import List, Dict, Any

# Assume sherlockscan is installed or PYTHONPATH is set correctly
from sherlockscan.scanner.explainer import generate_overall_explanation, RISK_LEVEL_RECOMMENDATIONS

# Disable logging during tests
logging.disable(logging.CRITICAL)

class TestExplainer(unittest.TestCase):
    """Unit tests for the explainer module."""

    def test_no_findings(self):
        """Test explanation generation when there are no findings."""
        findings: List[Dict[str, Any]] = []
        summary = {"total_findings": 0, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
        package_name = "clean-package"
        risk_level = "LOW" # Assume LOW if no findings
        
        expected_start = f"Package '{package_name}' analysis completed with no findings"
        expected_end = RISK_LEVEL_RECOMMENDATIONS["LOW"]
        
        explanation = generate_overall_explanation(findings, summary, package_name, risk_level)
        
        self.assertTrue(explanation.startswith(expected_start), "Explanation should indicate no findings.")
        self.assertTrue(explanation.endswith(expected_end), "Explanation should include the LOW risk recommendation.")
        self.assertIn("Risk level: LOW", explanation)

    def test_critical_findings_only(self):
        """Test explanation with only critical findings."""
        findings = [
            {"type": "Hardcoded Secret", "severity": "CRITICAL"},
            {"type": "Install Script Execution", "severity": "CRITICAL"},
        ]
        summary = {"total_findings": 2, "by_severity": {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
        package_name = "critical-package"
        risk_level = "CRITICAL"
        
        explanation = generate_overall_explanation(findings, summary, package_name, risk_level)
        
        self.assertIn(f"overall risk level of {risk_level}", explanation)
        self.assertIn("Critical issues found", explanation)
        self.assertIn("contains hardcoded secrets", explanation) # Check for summary phrase
        self.assertIn("executes commands or code during installation", explanation) # Check for summary phrase
        self.assertNotIn("High severity issues found", explanation)
        self.assertNotIn("Medium severity issues found", explanation)
        self.assertTrue(explanation.endswith(RISK_LEVEL_RECOMMENDATIONS["CRITICAL"]), "Should include CRITICAL recommendation.")

    def test_high_findings_only(self):
        """Test explanation with only high findings."""
        findings = [
            {"type": "Subprocess Execution", "severity": "HIGH"},
            {"type": "Dynamic Loading", "severity": "HIGH"},
        ]
        summary = {"total_findings": 2, "by_severity": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
        package_name = "high-risk-package"
        risk_level = "HIGH"
        
        explanation = generate_overall_explanation(findings, summary, package_name, risk_level)
        
        self.assertIn(f"overall risk level of {risk_level}", explanation)
        self.assertNotIn("Critical issues found", explanation)
        self.assertIn("High severity issues found", explanation)
        self.assertIn("can execute external commands", explanation)
        self.assertIn("uses dynamic code loading features", explanation)
        self.assertNotIn("Medium severity issues found", explanation)
        self.assertTrue(explanation.endswith(RISK_LEVEL_RECOMMENDATIONS["HIGH"]), "Should include HIGH recommendation.")

    def test_medium_findings_only(self):
        """Test explanation with only medium findings."""
        findings = [
            {"type": "Network Activity", "severity": "MEDIUM"},
            {"type": "High Entropy", "severity": "MEDIUM"},
        ]
        summary = {"total_findings": 2, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 0, "INFO": 0}}
        package_name = "medium-risk-package"
        risk_level = "MEDIUM"
        
        explanation = generate_overall_explanation(findings, summary, package_name, risk_level)
        
        self.assertIn(f"overall risk level of {risk_level}", explanation)
        self.assertNotIn("Critical issues found", explanation)
        self.assertNotIn("High severity issues found", explanation)
        self.assertIn("Medium severity issues found", explanation) # Should mention medium if no higher
        self.assertIn("performs network operations", explanation)
        self.assertIn("contains high entropy strings", explanation)
        self.assertTrue(explanation.endswith(RISK_LEVEL_RECOMMENDATIONS["MEDIUM"]), "Should include MEDIUM recommendation.")

    def test_low_info_findings_only(self):
        """Test explanation with only low/info findings."""
        findings = [
            {"type": "Keyword Match", "severity": "LOW"},
            {"type": "Install Script Custom Build", "severity": "INFO"},
        ]
        summary = {"total_findings": 2, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 1}}
        package_name = "low-risk-package"
        risk_level = "LOW" # Assume LOW if highest is LOW/INFO
        
        explanation = generate_overall_explanation(findings, summary, package_name, risk_level)
        
        self.assertIn(f"overall risk level of {risk_level}", explanation)
        self.assertNotIn("Critical issues found", explanation)
        self.assertNotIn("High severity issues found", explanation)
        self.assertNotIn("Medium severity issues found", explanation)
        self.assertIn("Main findings are informational or low severity.", explanation)
        self.assertTrue(explanation.endswith(RISK_LEVEL_RECOMMENDATIONS["LOW"]), "Should include LOW recommendation.")

    def test_mixed_severity_critical_highest(self):
        """Test explanation with mixed findings where CRITICAL is highest."""
        findings = [
            {"type": "Hardcoded Secret", "severity": "CRITICAL"},
            {"type": "Subprocess Execution", "severity": "HIGH"},
            {"type": "Network Activity", "severity": "MEDIUM"},
            {"type": "Keyword Match", "severity": "LOW"},
        ]
        summary = {"total_findings": 4, "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0}}
        package_name = "mixed-critical-package"
        risk_level = "CRITICAL"
        
        explanation = generate_overall_explanation(findings, summary, package_name, risk_level)
        
        self.assertIn(f"overall risk level of {risk_level}", explanation)
        self.assertIn("Critical issues found", explanation)
        self.assertIn("contains hardcoded secrets", explanation)
        # Should also mention High severity types if Critical exists
        self.assertIn("High severity issues found", explanation)
        self.assertIn("can execute external commands", explanation)
        # Should NOT mention Medium severity types if Critical/High exist
        self.assertNotIn("Medium severity issues found", explanation)
        self.assertTrue(explanation.endswith(RISK_LEVEL_RECOMMENDATIONS["CRITICAL"]), "Should include CRITICAL recommendation.")

    def test_mixed_severity_high_highest(self):
        """Test explanation with mixed findings where HIGH is highest."""
        findings = [
            {"type": "Subprocess Execution", "severity": "HIGH"},
            {"type": "Network Activity", "severity": "MEDIUM"},
            {"type": "Keyword Match", "severity": "LOW"},
        ]
        summary = {"total_findings": 3, "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0}}
        package_name = "mixed-high-package"
        risk_level = "HIGH"
        
        explanation = generate_overall_explanation(findings, summary, package_name, risk_level)
        
        self.assertIn(f"overall risk level of {risk_level}", explanation)
        self.assertNotIn("Critical issues found", explanation)
        self.assertIn("High severity issues found", explanation)
        self.assertIn("can execute external commands", explanation)
        # Should NOT mention Medium severity types if High exists
        self.assertNotIn("Medium severity issues found", explanation)
        self.assertTrue(explanation.endswith(RISK_LEVEL_RECOMMENDATIONS["HIGH"]), "Should include HIGH recommendation.")


if __name__ == '__main__':
    unittest.main()

