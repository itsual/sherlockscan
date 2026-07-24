#!/usr/bin/env python
# coding: utf-8

# sherlockscan/scanner/deps.py

import logging
import re
import yaml
import os
from typing import List, Dict, Any, Set, Optional

try:
    from importlib import metadata as importlib_metadata
except ImportError:
    try:
        import importlib_metadata # type: ignore
    except ImportError:
        logging.error("Error: importlib.metadata (or backport) not found. Dependency scanning requires Python 3.8+ or `pip install importlib-metadata`.")
        importlib_metadata = None # type: ignore 

try:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
except ImportError:
     logging.error("Error: 'packaging' library not found. Please install it: `pip install packaging`")
     Requirement = None # type: ignore
     canonicalize_name = None # type: ignore

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def load_approved_packages(config_path: str) -> Dict[str, Set[str]]:
    approved_config: Dict[str, Set[str]] = {
        "allowlist": set(),
        "blocklist": set()
    }
    if not os.path.exists(config_path):
        logging.info(f"Optional approved packages config not found: {config_path}. No allow/block lists applied.")
        return approved_config
        
    if canonicalize_name is None:
        logging.error("Cannot load approved packages config because 'packaging' library is missing.")
        return approved_config

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
            if config_data is None:
                return approved_config

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
        return {"allowlist": set(), "blocklist": set()}
    except Exception as e:
        logging.error(f"Error loading configuration file {config_path}: {e}")
        return {"allowlist": set(), "blocklist": set()}


def get_package_dependencies(package_name: str) -> Optional[List[str]]:
    if importlib_metadata is None:
        logging.error("Dependency scanning unavailable (importlib.metadata missing).")
        return None
        
    try:
        dist = importlib_metadata.distribution(package_name)
        requirements = dist.requires
        return requirements if requirements else []
    except importlib_metadata.PackageNotFoundError:
        logging.warning(f"Package '{package_name}' not found in the current environment for dependency scanning.")
        return None
    except Exception as e:
        logging.error(f"Error retrieving dependencies for package '{package_name}': {e}")
        return None

def parse_requirement(req_string: str) -> Optional[str]:
    if Requirement is None or canonicalize_name is None:
        logging.error("Cannot parse requirement because 'packaging' library is missing.")
        match = re.match(r"^\s*([a-zA-Z0-9._-]+)", req_string)
        return match.group(1).lower().replace('_', '-') if match else None

    try:
        req = Requirement(req_string)
        return canonicalize_name(req.name)
    except Exception as e:
        logging.warning(f"Could not parse requirement string: '{req_string}'. Error: {e}")
        match = re.match(r"^\s*([a-zA-Z0-9._-]+)", req_string)
        return match.group(1).lower().replace('_', '-') if match else None


def scan_dependencies(package_name: str, config_path: str) -> List[Dict[str, Any]]:
    logging.info(f"Scanning dependencies for package: {package_name}")
    findings: List[Dict[str, Any]] = []
    
    if importlib_metadata is None or Requirement is None:
        logging.error("Dependency scanning prerequisites missing (importlib.metadata or packaging). Skipping.")
        return findings

    approved_config = load_approved_packages(config_path)
    allowlist = approved_config["allowlist"]
    blocklist = approved_config["blocklist"]
    enforce_allowlist = bool(allowlist)

    requirements = get_package_dependencies(package_name)
    if requirements is None:
        return findings

    scanned_deps: Set[str] = set()

    for req_string in requirements:
        dep_name = parse_requirement(req_string)
        if not dep_name:
            logging.warning(f"Skipping unparseable requirement: '{req_string}' for package '{package_name}'")
            continue
            
        if dep_name in scanned_deps:
            continue
        scanned_deps.add(dep_name)

        if dep_name in blocklist:
            finding = {
                "type": "Blocked Dependency",
                "severity": "CRITICAL",
                "file_path": "Package Metadata",
                "line_number": None,
                "code_snippet": f"Dependency: {dep_name} (from requirement: {req_string})",
                "message": f"Package '{package_name}' depends on a blocked package: '{dep_name}'."
            }
            findings.append(finding)
            logging.debug(f"Dependency Finding: {finding}")

        if enforce_allowlist and dep_name not in allowlist:
            finding = {
                "type": "Unapproved Dependency",
                "severity": "MEDIUM",
                "file_path": "Package Metadata",
                "line_number": None,
                "code_snippet": f"Dependency: {dep_name} (from requirement: {req_string})",
                "message": f"Package '{package_name}' depends on unapproved package: '{dep_name}'. It is not in the configured allowlist."
            }
            is_blocked = any(f['type'] == 'Blocked Dependency' and f['code_snippet'].startswith(f"Dependency: {dep_name}") for f in findings)
            if not is_blocked and finding not in findings:
                 findings.append(finding)
                 logging.debug(f"Dependency Finding: {finding}")

    return findings
