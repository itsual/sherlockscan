#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/cli.py

import typer
import logging
import os
import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# --- SherlockScan Core Imports ---
# Note: Assuming these modules and functions exist based on our plan.
# We'll need error handling if they are not found.
try:
    from sherlockscan.scanner import ast_scanner, heuristics, deps, install_script_analyzer
    from sherlockscan.report import json_formatter, markdown_formatter
    from sherlockscan.scanner import explainer
    from sherlockscan import utils
except ImportError as e:
    print(f"Error: Failed to import SherlockScan modules. Make sure the package is installed correctly or PYTHONPATH is set.")
    print(f"Details: {e}")
    sys.exit(1)

# --- Library Imports ---
try:
    from importlib import metadata as importlib_metadata
except ImportError:
    try:
        import importlib_metadata # type: ignore
    except ImportError:
        print("Error: importlib.metadata (or backport) not found. Dependency scanning requires Python 3.8+ or `pip install importlib-metadata`.")
        importlib_metadata = None # type: ignore 

# --- Configuration ---
# Configure logging for the CLI tool
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
# Define severity order for risk calculation and filtering
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
DEFAULT_SEVERITY_THRESHOLD = "INFO" # Show all findings by default

# --- Typer App Initialization ---
app = typer.Typer(
    name="sherlockscan",
    help="SherlockScan: A tool to analyze Python packages for potential security risks.",
    add_completion=False
)

# --- Helper Functions ---

def _calculate_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates the summary of findings by severity."""
    summary = {
        "total_findings": len(findings),
        "by_severity": {severity: 0 for severity in SEVERITY_ORDER}
    }
    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        if severity in summary["by_severity"]:
            summary["by_severity"][severity] += 1
        else:
            # Handle potential UNKNOWN severity if needed
            if "UNKNOWN" not in summary["by_severity"]:
                 summary["by_severity"]["UNKNOWN"] = 0
            summary["by_severity"]["UNKNOWN"] += 1
            
    return summary

def _determine_overall_risk(summary: Dict[str, Any]) -> str:
    """Determines the overall risk level based on the highest severity finding."""
    severity_counts = summary.get("by_severity", {})
    for severity in SEVERITY_ORDER: # Check from highest to lowest
        if severity_counts.get(severity, 0) > 0:
            return severity
    return "INFO" # Default to INFO if no findings or only unknown

def _filter_findings_by_severity(findings: List[Dict[str, Any]], min_severity: str) -> List[Dict[str, Any]]:
    """Filters findings to include only those at or above the minimum severity level."""
    if min_severity not in SEVERITY_ORDER:
        logging.warning(f"Invalid severity level '{min_severity}'. Using default '{DEFAULT_SEVERITY_THRESHOLD}'.")
        min_severity = DEFAULT_SEVERITY_THRESHOLD
        
    min_severity_index = SEVERITY_ORDER.index(min_severity)
    
    filtered_findings = []
    for finding in findings:
        finding_severity = finding.get("severity", "UNKNOWN")
        try:
            finding_severity_index = SEVERITY_ORDER.index(finding_severity)
            if finding_severity_index <= min_severity_index: # Lower index means higher severity
                filtered_findings.append(finding)
        except ValueError:
             # Handle UNKNOWN or unexpected severity values - include them by default? Or exclude? Let's include.
             logging.debug(f"Including finding with unknown severity: {finding_severity}")
             filtered_findings.append(finding)
             
    return filtered_findings

def _get_package_path_and_info(target: str) -> Optional[Tuple[Path, str, Optional[str]]]:
    """Determines package directory, name, and version using utils.resolve_package_target."""
    logging.info(f"Resolving package target: {target}")
    try:
        return utils.resolve_package_target(target)
    except Exception as e:
        logging.error(f"Error resolving package '{target}': {e}")
        return None


def _find_python_files(package_dir: Path) -> List[Path]:
    """Finds all .py files within the package directory using utils.find_python_files."""
    return utils.find_python_files(package_dir)

# --- Typer Command ---

@app.command()
def scan(
    package_target: str = typer.Argument(..., help="Package name (from PyPI) or path to local package directory/archive."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Path to save the report file."),
    format: str = typer.Option("md", "--format", "-f", help="Output format ('json' or 'md'). Default is 'md'."),
    config_dir: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to the directory containing configuration files (risk_patterns.yaml, approved_packages.yaml). Defaults to './config'.") ,
    severity: str = typer.Option(DEFAULT_SEVERITY_THRESHOLD, "--severity", "-s", help=f"Minimum severity level to report ({', '.join(SEVERITY_ORDER)}). Default: {DEFAULT_SEVERITY_THRESHOLD}.")
):
    """
    Analyzes a Python package for potential security risks.
    """
    logging.info(f"Starting SherlockScan for target: {package_target}")

    # --- 1. Resolve Configuration Paths ---
    if config_dir is None:
        # Default config location relative to where sherlockscan might be installed or run
        # This might need adjustment based on packaging strategy
        config_dir = Path("./config") # Assume config dir is in current working dir or package root
        logging.info(f"No config directory specified, using default: {config_dir.absolute()}")
    
    if not config_dir.is_dir():
         logging.warning(f"Configuration directory not found: {config_dir}. Using default scanner settings and no allow/block lists.")
         # Scanners should handle non-existent config files gracefully

    risk_patterns_path = config_dir / "risk_patterns.yaml"
    approved_packages_path = config_dir / "approved_packages.yaml"

    # --- 2. Resolve Package Path and Info ---
    package_info = _get_package_path_and_info(package_target)
    if not package_info:
        logging.error("Failed to resolve package target. Exiting.")
        raise typer.Exit(code=1)
    package_dir, package_name, package_version = package_info
    logging.info(f"Resolved package: Name='{package_name}', Version='{package_version}', Path='{package_dir}'")


    # --- 3. Run Scanners ---
    all_findings: List[Dict[str, Any]] = []
    
    # 3a. Install Script Analysis (setup.py, pyproject.toml)
    logging.info("Running install script analysis...")
    try:
        all_findings.extend(install_script_analyzer.scan_install_scripts(str(package_dir)))
    except Exception as e:
        logging.error(f"Error during install script analysis: {e}", exc_info=True) # Log traceback

    # 3b. Dependency Analysis (requires package name)
    logging.info("Running dependency analysis...")
    try:
        # Ensure config path is passed correctly
        dep_findings = deps.scan_dependencies(package_name, str(approved_packages_path))
        all_findings.extend(dep_findings)
    except Exception as e:
        logging.error(f"Error during dependency analysis: {e}", exc_info=True)

    # 3c. Source Code Analysis (AST and Heuristics for all .py files)
    logging.info("Running source code analysis (AST & Heuristics)...")
    python_files = _find_python_files(package_dir)
    if not python_files:
         logging.warning(f"No Python files found in {package_dir} to scan.")
         
    for py_file in python_files:
        try:
            logging.debug(f"Scanning file: {py_file}")
            # Ensure config path is passed correctly
            all_findings.extend(ast_scanner.scan_file_ast(str(py_file)))
            all_findings.extend(heuristics.scan_file_heuristics(str(py_file), str(risk_patterns_path)))
        except Exception as e:
             logging.error(f"Error scanning file {py_file}: {e}", exc_info=True)


    # --- 4. Process Results ---
    logging.info("Processing scan results...")
    
    # Filter by severity
    original_count = len(all_findings)
    filtered_findings = _filter_findings_by_severity(all_findings, severity.upper())
    filtered_count = len(filtered_findings)
    logging.info(f"Total findings: {original_count}. Findings after filtering (severity >= {severity.upper()}): {filtered_count}")

    # Calculate summary and risk level based on *filtered* findings
    summary = _calculate_summary(filtered_findings)
    overall_risk_level = _determine_overall_risk(summary)
    logging.info(f"Calculated overall risk level: {overall_risk_level}")

    # Generate explanation
    explanation = explainer.generate_overall_explanation(
        filtered_findings, summary, package_name, overall_risk_level
    )

    # --- 5. Format Output ---
    output_content = ""
    if format.lower() == "json":
        logging.info("Formatting report as JSON...")
        output_content = json_formatter.format_report_json(
            package_name=package_name,
            package_version=package_version,
            findings=filtered_findings,
            summary=summary,
            overall_risk_level=overall_risk_level,
            explanation=explanation
        )
    elif format.lower() == "md":
        logging.info("Formatting report as Markdown...")
        output_content = markdown_formatter.format_report_markdown(
            package_name=package_name,
            package_version=package_version,
            findings=filtered_findings,
            summary=summary,
            overall_risk_level=overall_risk_level,
            explanation=explanation
        )
    else:
        logging.error(f"Invalid output format specified: '{format}'. Use 'json' or 'md'.")
        raise typer.Exit(code=1)

    # --- 6. Output Report ---
    if output:
        try:
            output.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
            with open(output, 'w', encoding='utf-8') as f:
                f.write(output_content)
            logging.info(f"Report saved to: {output}")
        except Exception as e:
            logging.error(f"Failed to write report to file {output}: {e}")
            raise typer.Exit(code=1)
    else:
        # Print to console
        typer.echo(output_content)

    logging.info("SherlockScan finished.")
    
    # Exit with code indicating risk level? (e.g., 0=OK, 1=Warn, 2=Error) - Optional enhancement
    # if overall_risk_level in ["CRITICAL", "HIGH"]:
    #     raise typer.Exit(code=2)
    # elif overall_risk_level == "MEDIUM":
    #      raise typer.Exit(code=1)


# --- Main Execution Guard ---
if __name__ == "__main__":
    # Add dummy config files if they don't exist for basic testing when run directly
    if not Path("./config").exists(): Path("./config").mkdir()
    if not Path("./config/risk_patterns.yaml").exists(): Path("./config/risk_patterns.yaml").touch()
    if not Path("./config/approved_packages.yaml").exists(): Path("./config/approved_packages.yaml").touch()
    
    app()


