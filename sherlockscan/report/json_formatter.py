#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/report/json_formatter.py

import json
import logging
import datetime
from datetime import timezone
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def format_report_json(
    package_name: str,
    package_version: Optional[str],
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any], # Expects {'total_findings': int, 'by_severity': {'CRITICAL': int, ...}}
    overall_risk_level: str, # e.g., "HIGH", "CRITICAL"
    explanation: str
) -> str:
    """
    Formats the scan results into a JSON string according to the defined structure.

    Args:
        package_name: The name of the scanned package.
        package_version: The version of the scanned package (if available).
        findings: The list of individual finding dictionaries.
        summary: A dictionary summarizing finding counts.
        overall_risk_level: The calculated overall risk level string.
        explanation: The generated overall explanation string.

    Returns:
        A JSON string representing the report, or an empty JSON object string on error.
    """
    logging.debug(f"Formatting report to JSON for package: {package_name}")

    # Get current timestamp in ISO 8601 format (UTC)
    scan_timestamp = datetime.datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # Construct the report dictionary
    report_data = {
        "package_name": package_name,
        "package_version": package_version, # Will be null if not provided
        "scan_timestamp": scan_timestamp,
        "overall_risk_level": overall_risk_level,
        "findings": findings,
        "summary": summary,
        "explanation": explanation
    }

    try:
        # Serialize the dictionary to a pretty-printed JSON string
        json_report = json.dumps(report_data, indent=2, ensure_ascii=False)
        return json_report
    except TypeError as e:
        logging.error(f"Error serializing report data to JSON for package '{package_name}': {e}")
        # Fallback: return an empty JSON object string
        return "{}"
    except Exception as e:
        logging.error(f"An unexpected error occurred during JSON formatting for package '{package_name}': {e}")
        return "{}"

# Example Usage (for testing purposes)
if __name__ == '__main__':

    # Sample data matching the structure expected by the function
    sample_package_name = "example-package"
    sample_package_version = "1.0.1-beta"
    sample_findings = [
        {
            "type": "Hardcoded Secret",
            "severity": "CRITICAL",
            "file_path": "example_package/secrets.py",
            "line_number": 10,
            "code_snippet": "API_KEY = \"sk_live_...\"",
            "message": "Hardcoded Stripe API Key detected."
        },
        {
            "type": "Risky Call",
            "severity": "HIGH",
            "file_path": "example_package/utils.py",
            "line_number": 55,
            "code_snippet": "result = eval(user_input)",
            "message": "Use of 'eval' detected. Executing arbitrary strings as code is highly dangerous."
        }
    ]
    sample_summary = {
        "total_findings": 2,
        "by_severity": {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
    }
    sample_risk_level = "CRITICAL"
    sample_explanation = (
        "Package 'example-package' analysis resulted in an overall risk level of CRITICAL. "
        "Critical issues found: Package contains hardcoded secrets (e.g., API keys, passwords), "
        "uses potentially dangerous functions like eval/exec. "
        "Strongly recommend avoiding use and performing an immediate, thorough code audit if usage is unavoidable."
    )

    print(f"--- Generating JSON Report for: {sample_package_name} ---")

    # Generate the JSON report string
    json_output = format_report_json(
        package_name=sample_package_name,
        package_version=sample_package_version,
        findings=sample_findings,
        summary=sample_summary,
        overall_risk_level=sample_risk_level,
        explanation=sample_explanation
    )

    # Print the result
    print("\nFormatted JSON Output:")
    print(json_output)

    print("\n--- Testing Error Case ---")
    # Example of data that might cause a TypeError during JSON serialization
    invalid_findings = [{"bad_data": datetime.datetime.now()}] # datetime objects aren't directly JSON serializable
    error_output = format_report_json(
         package_name="error-test",
         package_version="1.0",
         findings=invalid_findings, # type: ignore
         summary={"total_findings": 1, "by_severity": {"CRITICAL": 1}},
         overall_risk_level="CRITICAL",
         explanation="Error test"
    )
    print("Output on TypeError:")
    print(error_output) # Should print "{}"


