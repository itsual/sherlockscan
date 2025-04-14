#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/scanner/heuristics.py

import re
import math
import logging
import yaml
import os
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default entropy threshold - adjust as needed based on testing
DEFAULT_ENTROPY_THRESHOLD = 4.0

# --- Helper Functions ---

def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    
    # Calculate frequency of each character
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    
    # Calculate Shannon entropy
    entropy = -sum([p * math.log2(p) for p in prob])
    return entropy

def load_risk_patterns(config_path: str) -> Dict[str, Any]:
    """
    Loads risk patterns (regex, keywords, settings) from a YAML config file.
    
    Args:
        config_path: Path to the risk_patterns.yaml file.

    Returns:
        A dictionary containing the loaded patterns and settings. 
        Returns an empty dictionary if loading fails.
    """
    default_patterns = {
        "regex_patterns": [],
        "keywords": [],
        "settings": {"entropy_threshold": DEFAULT_ENTROPY_THRESHOLD}
    }
    if not os.path.exists(config_path):
        logging.warning(f"Configuration file not found: {config_path}. Using empty patterns.")
        return default_patterns
        
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            patterns = yaml.safe_load(f)
            if patterns is None:
                return default_patterns
            # Ensure top-level keys exist
            if "regex_patterns" not in patterns: patterns["regex_patterns"] = []
            if "keywords" not in patterns: patterns["keywords"] = []
            if "settings" not in patterns: patterns["settings"] = {}
            if "entropy_threshold" not in patterns["settings"]:
                 patterns["settings"]["entropy_threshold"] = DEFAULT_ENTROPY_THRESHOLD
            return patterns
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML configuration file {config_path}: {e}")
        return default_patterns
    except Exception as e:
        logging.error(f"Error loading configuration file {config_path}: {e}")
        return default_patterns

# --- Main Scanning Function ---

def scan_file_heuristics(file_path: str, config_path: str) -> List[Dict[str, Any]]:
    """
    Scans a file for heuristic patterns like secrets, keywords, and high entropy.

    Args:
        file_path: Path to the file to scan.
        config_path: Path to the risk_patterns.yaml configuration file.

    Returns:
        A list of findings (dictionaries).
    """
    logging.info(f"Scanning file with heuristics: {file_path}")
    findings: List[Dict[str, Any]] = []
    
    # Load patterns from config
    risk_patterns = load_risk_patterns(config_path)
    regex_patterns = risk_patterns.get("regex_patterns", [])
    keywords = risk_patterns.get("keywords", [])
    entropy_threshold = risk_patterns.get("settings", {}).get("entropy_threshold", DEFAULT_ENTROPY_THRESHOLD)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line_stripped = line.strip()
                if not line_stripped: # Skip empty lines
                    continue

                # 1. Regex Scan (Secrets, specific patterns)
                for pattern_info in regex_patterns:
                    name = pattern_info.get("name", "Unnamed Regex Pattern")
                    pattern = pattern_info.get("pattern")
                    severity = pattern_info.get("severity", "MEDIUM")
                    message_template = pattern_info.get("message", f"Potential '{name}' detected.")
                    
                    if not pattern:
                        logging.warning(f"Skipping regex pattern '{name}' due to missing 'pattern' field in config.")
                        continue
                        
                    try:
                        # Use re.IGNORECASE for broader matching? Configurable? For now, case-sensitive.
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            finding = {
                                "type": pattern_info.get("type", "Heuristic Match"), # e.g., "Hardcoded Secret"
                                "severity": severity,
                                "file_path": file_path,
                                "line_number": line_num,
                                "code_snippet": line_stripped[:150], # Limit snippet length
                                "message": message_template.format(match=match.group(0)) # Allow message formatting
                            }
                            if finding not in findings:
                                findings.append(finding)
                                logging.debug(f"Heuristic Regex Finding: {finding}")
                    except re.error as e:
                         logging.warning(f"Invalid regex pattern '{name}' in config: {pattern}. Error: {e}")
                         # Prevent this pattern from being used again in this run
                         pattern_info["pattern"] = None # Mark as invalid


                # 2. Keyword Scan
                line_lower = line.lower() # Case-insensitive keyword search
                for keyword_info in keywords:
                    name = keyword_info.get("name", "Unnamed Keyword")
                    keyword = keyword_info.get("keyword")
                    severity = keyword_info.get("severity", "LOW")
                    message_template = keyword_info.get("message", f"Suspicious keyword '{keyword}' found.")
                    
                    if not keyword:
                        logging.warning(f"Skipping keyword '{name}' due to missing 'keyword' field in config.")
                        continue

                    if keyword.lower() in line_lower:
                         finding = {
                            "type": keyword_info.get("type", "Keyword Match"),
                            "severity": severity,
                            "file_path": file_path,
                            "line_number": line_num,
                            "code_snippet": line_stripped[:150],
                            "message": message_template.format(keyword=keyword)
                         }
                         if finding not in findings:
                            findings.append(finding)
                            logging.debug(f"Heuristic Keyword Finding: {finding}")

                # 3. Entropy Scan (on the stripped line for now)
                # More advanced: could extract variable names, string literals via AST first
                # For MVP heuristic scan, check entropy of reasonably long strings/lines
                if len(line_stripped) > 20: # Only check entropy on longer lines/strings
                    entropy = calculate_entropy(line_stripped)
                    if entropy > entropy_threshold:
                        finding = {
                            "type": "High Entropy",
                            "severity": "MEDIUM", # Usually medium, needs context
                            "file_path": file_path,
                            "line_number": line_num,
                            "code_snippet": line_stripped[:150],
                            "message": f"High Shannon entropy ({entropy:.2f}) detected, potentially indicating obfuscated or packed data (threshold: {entropy_threshold:.2f})."
                        }
                        # Avoid adding duplicate entropy warnings for same line if already added
                        if finding not in findings:
                             findings.append(finding)
                             logging.debug(f"Heuristic Entropy Finding: {finding}")

    except FileNotFoundError:
        logging.error(f"File not found during heuristic scan: {file_path}")
        return []
    except Exception as e:
        logging.error(f"Error reading file {file_path} during heuristic scan: {e}")
        return []
        
    return findings

# Example Usage (for testing purposes)
if __name__ == '__main__':
    import tempfile
    import os

    # Create dummy config content
    dummy_config_content = """
regex_patterns:
  - name: AWS Access Key ID
    type: Hardcoded Secret
    pattern: '(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])' # Basic example, needs refinement
    severity: CRITICAL
    message: "Potential AWS Access Key ID detected."
  - name: Generic Password Variable
    type: Hardcoded Secret
    pattern: '(?i)password\s*=\s*["\'](.*?)["\']' # Finds password = "..."
    severity: HIGH
    message: "Potential hardcoded password variable detected."

keywords:
  - name: TODO Security
    type: Security Comment
    keyword: "TODO: security"
    severity: LOW
    message: "Comment indicates a potential security task."
  - name: HACK Keyword
    type: Suspicious Comment
    keyword: "HACK:"
    severity: MEDIUM
    message: "Keyword 'HACK:' found in comments."

settings:
  entropy_threshold: 4.0 
"""

    # Create dummy file content
    dummy_code_content = """
import os

# Credentials - BAD!
aws_key = "AKIAIOSFODNN7EXAMPLE" 
password = "MySuperSecretPassword123" 
another_var = "thisisjustaregularstring"

# High entropy string - maybe obfuscated?
obfuscated = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" # EICAR test string has high entropy

# Keywords
# TODO: security - need to fix this later
# HACK: Quick fix for demo

def normal_function():
    print("Hello")
"""

    # Create temporary config file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml', encoding='utf-8') as tmp_config_file:
        tmp_config_file.write(dummy_config_content)
        tmp_config_path = tmp_config_file.name

    # Create temporary python file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py', encoding='utf-8') as tmp_code_file:
        tmp_code_file.write(dummy_code_content)
        tmp_code_path = tmp_code_file.name

    print(f"Scanning dummy file: {tmp_code_path}")
    print(f"Using dummy config: {tmp_config_path}")
    
    findings = scan_file_heuristics(tmp_code_path, tmp_config_path)
    
    print("\nFindings:")
    if findings:
        for finding in findings:
            print(f"- {finding['type']} ({finding['severity']}) at {finding['file_path']}:{finding['line_number']}")
            print(f"  Message: {finding['message']}")
            print(f"  Snippet: {finding['code_snippet']}")
    else:
        print("No findings.")

    # Clean up temporary files
    os.remove(tmp_config_path)
    os.remove(tmp_code_path)
    print(f"\nCleaned up dummy files.")


