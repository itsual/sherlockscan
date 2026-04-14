#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/scanner/deps.py

import logging
import re
import yaml
import os
from typing import List, Dict, Any, Set, Optional

# Attempt to import metadata; handle Python < 3.8 or environment issues
try:
    from importlib import metadata as importlib_metadata
except ImportError:
    # Fallback for Python < 3.8 (requires importlib_metadata backport installed)
    try:
        import importlib_metadata # type: ignore
    except ImportError:
        logging.error("Error: importlib.metadata (or backport) not found. Dependency scanning requires Python 3.8+ or `pip install importlib-metadata`.")
        # Define dummy functions or raise to prevent execution
        importlib_metadata = None # type: ignore 

# Import packaging for requirement parsing
try:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
except ImportError:
     logging.error("Error: 'packaging' library not found. Please install it: `pip install packaging`")
     Requirement = None # type: ignore
     canonicalize_name = None # type: ignore

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def load_approved_packages(config_path: str) -> Dict[str, Set[str]]:
    """
    Loads allow/block lists from the approved_packages.yaml config file.

    Args:
        config_path: Path to the approved_packages.yaml file.

    Returns:
        A dictionary with 'allowlist' and 'blocklist' sets (canonicalized names).
        Returns empty sets if loading fails or file doesn't exist.
    """
    approved_config: Dict[str, Set[str]] = {
        "allowlist": set(),
        "blocklist": set()
    }
    if not os.path.exists(config_path):
        # It's okay if this file doesn't exist, means no specific lists are enforced
        logging.info(f"Optional approved packages config not found: {config_path}. No allow/block lists applied.")
        return approved_config
        
    if canonicalize_name is None:
        logging.error("Cannot load approved packages config because 'packaging' library is missing.")
        return approved_config # Return empty if packaging lib missing

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
            if config_data is None:
                return approved_config

            # Load and canonicalize names for consistent comparison
            raw_allowlist = config_data.get("allowlist", [])
            raw_blocklist = config_data.get("blocklist", [])

            if isinstance(raw_allowlist, list):
                 approved_config["allowlist"] = {canonicalize_name(pkg) for pkg in raw_allowlist if isinstance(pkg, str)}
            else:
                 logging.warning(f"Invalid format for 'allowlist' in {config_path}. Expected a list.")

            if isinstance(raw_blocklist, list):
                 approved_config["blocklist"] = {canonicalize_name(pkg) for pkg in raw_blocklist if isinstance(pkg, str)}
            else:
                 logging.warning(f"Invalid format for 'blocklist' in {config_path}. Expected a list.")

            return approved_config
            
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML configuration file {config_path}: {e}")
        return {"allowlist": set(), "blocklist": set()} # Return empty on error
    except Exception as e:
        logging.error(f"Error loading configuration file {config_path}: {e}")
        return {"allowlist": set(), "blocklist": set()} # Return empty on error


def get_package_dependencies(package_name: str) -> Optional[List[str]]:
    """
    Retrieves the list of requirement strings for an installed package.

    Args:
        package_name: The canonical name of the package to query.

    Returns:
        A list of requirement strings (e.g., "requests>=2.0"), 
        or None if the package is not found or metadata cannot be read.
    """
    if importlib_metadata is None:
        logging.error("Dependency scanning unavailable (importlib.metadata missing).")
        return None
        
    try:
        # Get distribution for the package name
        dist = importlib_metadata.distribution(package_name)
        # Retrieve requires.txt metadata (dependencies)
        requirements = dist.requires
        return requirements if requirements else [] # Return empty list if None
    except importlib_metadata.PackageNotFoundError:
        logging.warning(f"Package '{package_name}' not found in the current environment for dependency scanning.")
        return None
    except Exception as e:
        logging.error(f"Error retrieving dependencies for package '{package_name}': {e}")
        return None

def parse_requirement(req_string: str) -> Optional[str]:
    """
    Parses a requirement string to get the canonical package name.

    Args:
        req_string: The requirement string (e.g., "requests>=2.0", "numpy").

    Returns:
        The canonicalized package name (e.g., "requests", "numpy"), or None if parsing fails.
    """
    if Requirement is None or canonicalize_name is None:
        logging.error("Cannot parse requirement because 'packaging' library is missing.")
        # Basic fallback (less reliable)
        match = re.match(r"^\s*([a-zA-Z0-9._-]+)", req_string)
        return match.group(1).lower().replace('_', '-') if match else None

    try:
        req = Requirement(req_string)
        return canonicalize_name(req.name)
    except Exception as e: # Catch potential parsing errors from `packaging`
        logging.warning(f"Could not parse requirement string: '{req_string}'. Error: {e}")
        # Attempt basic fallback if packaging fails
        match = re.match(r"^\s*([a-zA-Z0-9._-]+)", req_string)
        return match.group(1).lower().replace('_', '-') if match else None


# --- Main Scanning Function ---

def scan_dependencies(package_name: str, config_path: str) -> List[Dict[str, Any]]:
    """
    Scans the direct dependencies of an installed package against allow/block lists.

    Args:
        package_name: The canonical name of the package to scan.
        config_path: Path to the approved_packages.yaml configuration file.

    Returns:
        A list of findings (dictionaries) related to dependencies.
    """
    logging.info(f"Scanning dependencies for package: {package_name}")
    findings: List[Dict[str, Any]] = []
    
    if importlib_metadata is None or Requirement is None:
        logging.error("Dependency scanning prerequisites missing (importlib.metadata or packaging). Skipping.")
        return findings # Cannot proceed without required libs

    # Load allow/block lists
    approved_config = load_approved_packages(config_path)
    allowlist = approved_config["allowlist"]
    blocklist = approved_config["blocklist"]
    enforce_allowlist = bool(allowlist) # Only enforce allowlist if it's explicitly defined and not empty

    # Get dependencies
    requirements = get_package_dependencies(package_name)
    if requirements is None:
        # Error logged in get_package_dependencies
        return findings # Cannot proceed if dependencies couldn't be retrieved

    scanned_deps: Set[str] = set()

    for req_string in requirements:
        dep_name = parse_requirement(req_string)
        if not dep_name:
            logging.warning(f"Skipping unparseable requirement: '{req_string}' for package '{package_name}'")
            continue
            
        # Avoid duplicate checks if a package is listed multiple times (e.g., with different extras)
        if dep_name in scanned_deps:
            continue
        scanned_deps.add(dep_name)

        # 1. Check Blocklist
        if dep_name in blocklist:
            finding = {
                "type": "Blocked Dependency",
                "severity": "CRITICAL", # Blocked dependencies are usually critical
                "file_path": "Package Metadata", # Indicate finding is from metadata
                "line_number": None, # Not applicable to dependency list
                "code_snippet": f"Dependency: {dep_name} (from requirement: {req_string})",
                "message": f"Package '{package_name}' depends on a blocked package: '{dep_name}'."
            }
            findings.append(finding)
            logging.debug(f"Dependency Finding: {finding}")
            # Continue checking other rules even if blocked

        # 2. Check Allowlist (only if an allowlist is defined)
        if enforce_allowlist and dep_name not in allowlist:
            finding = {
                "type": "Unapproved Dependency",
                "severity": "MEDIUM", # Unapproved might be medium/low depending on policy
                "file_path": "Package Metadata",
                "line_number": None,
                "code_snippet": f"Dependency: {dep_name} (from requirement: {req_string})",
                "message": f"Package '{package_name}' depends on unapproved package: '{dep_name}'. It is not in the configured allowlist."
            }
            # Avoid adding duplicate unapproved warnings if already blocked
            is_blocked = any(f['type'] == 'Blocked Dependency' and f['code_snippet'].startswith(f"Dependency: {dep_name}") for f in findings)
            if not is_blocked and finding not in findings:
                 findings.append(finding)
                 logging.debug(f"Dependency Finding: {finding}")

    # --- Stretch Goal: Vulnerability Scanning ---
    # Here you would iterate through 'scanned_deps' and query a vulnerability
    # database (e.g., OSV API) for known CVEs associated with each dependency name + version.
    # This requires handling versions extracted during requirement parsing and making network requests.
    # Example placeholder:
    # for dep_name in scanned_deps:
    #     version = get_installed_version(dep_name) # Needs implementation
    #     if version:
    #         vulnerabilities = query_vuln_db(dep_name, version) # Needs implementation
    #         for vuln in vulnerabilities:
    #             findings.append({ ... vulnerability finding ... })

    return findings


# Example Usage (for testing purposes)
if __name__ == '__main__':
    import tempfile
    import os
    from unittest.mock import patch, MagicMock

    # Create dummy config content
    dummy_config_content = """
allowlist:
  - requests
  - PyYAML
  - packaging # Allow packaging itself
  # Note: Names are canonicalized (lowercase, dashes)

blocklist:
  - insecure-package 
  - another-bad-one
"""

    # Create temporary config file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml', encoding='utf-8') as tmp_config_file:
        tmp_config_file.write(dummy_config_content)
        tmp_config_path = tmp_config_file.name

    print(f"Using dummy config: {tmp_config_path}")

    # --- Mocking importlib.metadata ---
    # We mock the dependencies instead of requiring installation
    
    # Mock distribution object
    mock_dist = MagicMock()
    # Define the dependencies for our mock package 'my-test-package'
    mock_dist.requires = [
        "requests>=2.0",                # Allowed
        "PyYAML",                       # Allowed (case test)
        "insecure-package==1.0",        # Blocked
        "unknown-dep~=3.1",             # Unapproved (will be flagged by allowlist)
        "packaging"                     # Allowed (meta)
    ]
    
    # Mock the distribution function to return our mock object
    mock_distribution_func = MagicMock(return_value=mock_dist)

    # Patch 'importlib_metadata.distribution' within the deps module's scope
    # Also ensure 'packaging' library components are available or mocked if needed
    if importlib_metadata and Requirement:
        with patch('sherlockscan.scanner.deps.importlib_metadata.distribution', mock_distribution_func):
            
            target_package = "my-test-package" # The package we pretend to scan
            print(f"\nScanning dependencies for mock package: {target_package}")
            
            findings = scan_dependencies(target_package, tmp_config_path)
            
            print("\nFindings:")
            if findings:
                for finding in findings:
                    print(f"- {finding['type']} ({finding['severity']})")
                    print(f"  Message: {finding['message']}")
                    print(f"  Detail: {finding['code_snippet']}")
            else:
                print("No findings.")
    else:
        print("\nSkipping test execution because importlib.metadata or packaging is missing.")


    # Clean up temporary file
    os.remove(tmp_config_path)
    print(f"\nCleaned up dummy config file.")

