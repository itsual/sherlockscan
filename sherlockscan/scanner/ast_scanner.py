#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/scanner/ast_scanner.py

import ast
import logging
from typing import List, Dict, Any, Tuple, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define risky elements to look for
# Structure: { 'type': 'Category', 'severity': 'Level', 'message': 'Explanation Template' }
# We will map specific functions/modules to these categories.

RISK_CATEGORIES = {
    # Execution Risks
    "eval": {"type": "Risky Call", "severity": "CRITICAL", "message": "Use of 'eval' detected. Executing arbitrary strings as code is highly dangerous."},
    "exec": {"type": "Risky Call", "severity": "CRITICAL", "message": "Use of 'exec' detected. Executing arbitrary code blocks is highly dangerous."},
    "compile": {"type": "Risky Call", "severity": "HIGH", "message": "Use of 'compile' detected. Can be used to compile arbitrary strings into code objects for 'eval' or 'exec'."},

    # Insecure Deserialization (Critical for ML)
    "pickle": {"type": "Insecure Deserialization", "severity": "CRITICAL", "message": "Use of 'pickle' module detected. Loading untrusted pickle files can lead to arbitrary code execution."},
    "dill": {"type": "Insecure Deserialization", "severity": "CRITICAL", "message": "Use of 'dill' module detected. Similar to pickle, loading untrusted dill files can lead to arbitrary code execution."},
    "shelve": {"type": "Insecure Deserialization", "severity": "HIGH", "message": "Use of 'shelve' module detected. Often uses pickle internally, posing similar risks if data source is untrusted."},

    # Subprocess Risks
    "os.system": {"type": "Subprocess Execution", "severity": "CRITICAL", "message": "Use of 'os.system' detected. Executes shell commands, potentially leading to command injection vulnerabilities."},
    "os.popen": {"type": "Subprocess Execution", "severity": "CRITICAL", "message": "Use of 'os.popen' detected. Executes shell commands, potentially leading to command injection vulnerabilities."},
    "subprocess": {"type": "Subprocess Execution", "severity": "HIGH", "message": "Use of 'subprocess' module detected. Allows running external commands; ensure shell=True is not used with untrusted input."},

    # Network Activity Risks
    "socket": {"type": "Network Activity", "severity": "MEDIUM", "message": "Use of 'socket' module detected. Indicates direct network communication capability."},
    "requests": {"type": "Network Activity", "severity": "MEDIUM", "message": "Use of 'requests' library detected. Indicates HTTP communication capability."},
    "urllib": {"type": "Network Activity", "severity": "MEDIUM", "message": "Use of 'urllib' module detected. Indicates network communication capability."},
    "http.client": {"type": "Network Activity", "severity": "MEDIUM", "message": "Use of 'http.client' module detected. Indicates HTTP communication capability."},
    "ftplib": {"type": "Network Activity", "severity": "MEDIUM", "message": "Use of 'ftplib' module detected. Indicates FTP communication capability."},
    "smtplib": {"type": "Network Activity", "severity": "MEDIUM", "message": "Use of 'smtplib' module detected. Indicates SMTP (email) communication capability."},

    # Dynamic Loading / Execution Risks
    "importlib": {"type": "Dynamic Loading", "severity": "MEDIUM", "message": "Use of 'importlib' detected. Allows dynamic importing of modules, potentially from untrusted sources."},
    "ctypes": {"type": "Dynamic Loading", "severity": "HIGH", "message": "Use of 'ctypes' detected. Allows calling functions in shared libraries (DLLs, .so files), potentially bypassing Python-level security."},
}

# Specific function calls and module attributes to map to categories
RISKY_CALLS: Dict[str, Dict] = {
    "eval": RISK_CATEGORIES["eval"],
    "exec": RISK_CATEGORIES["exec"],
    "compile": RISK_CATEGORIES["compile"],
    "pickle.load": RISK_CATEGORIES["pickle"],
    "pickle.loads": RISK_CATEGORIES["pickle"],
    "dill.load": RISK_CATEGORIES["dill"],
    "dill.loads": RISK_CATEGORIES["dill"],
    "shelve.open": RISK_CATEGORIES["shelve"],
    "os.system": RISK_CATEGORIES["os.system"],
    "os.popen": RISK_CATEGORIES["os.popen"],
    "subprocess.run": RISK_CATEGORIES["subprocess"],
    "subprocess.call": RISK_CATEGORIES["subprocess"],
    "subprocess.check_call": RISK_CATEGORIES["subprocess"],
    "subprocess.check_output": RISK_CATEGORIES["subprocess"],
    "subprocess.Popen": RISK_CATEGORIES["subprocess"],
    # Network related function calls could be added here if needed,
    # but module imports are often sufficient for initial flagging.
}

# Modules whose import alone is considered risky/noteworthy
RISKY_MODULE_IMPORTS: Dict[str, Dict] = {
    "pickle": RISK_CATEGORIES["pickle"],
    "dill": RISK_CATEGORIES["dill"],
    "shelve": RISK_CATEGORIES["shelve"],
    "subprocess": RISK_CATEGORIES["subprocess"],
    "socket": RISK_CATEGORIES["socket"],
    "requests": RISK_CATEGORIES["requests"],
    "urllib": RISK_CATEGORIES["urllib"],
    "http.client": RISK_CATEGORIES["http.client"],
    "ftplib": RISK_CATEGORIES["ftplib"],
    "smtplib": RISK_CATEGORIES["smtplib"],
    "importlib": RISK_CATEGORIES["importlib"],
    "ctypes": RISK_CATEGORIES["ctypes"],
    # os module is too common, specific functions are checked in RISKY_CALLS
}

class AstScannerVisitor(ast.NodeVisitor):
    """
    Visits nodes in an Abstract Syntax Tree (AST) to find risky patterns.
    """
    def __init__(self, file_path: str):
        self.findings: List[Dict[str, Any]] = []
        self.file_path: str = file_path
        # Keep track of imported names to resolve calls like requests.get
        self.imported_names: Dict[str, str] = {} # alias -> original_name

    def _add_finding(self, node: ast.AST, risk_info: Dict, code_snippet: str = "N/A"):
        """Helper method to add a finding."""
        finding = {
            "type": risk_info["type"],
            "severity": risk_info["severity"],
            "file_path": self.file_path,
            "line_number": node.lineno,
            "code_snippet": code_snippet, # Simple placeholder for now
            "message": risk_info["message"]
        }
        # Avoid duplicate findings for the same issue on the same line
        if finding not in self.findings:
            self.findings.append(finding)
            logging.debug(f"AST Finding Added: {finding}")

    def visit_Import(self, node: ast.Import):
        """Visit Import nodes."""
        for alias in node.names:
            module_name = alias.name
            # Store alias if present, otherwise alias is the module name itself
            self.imported_names[alias.asname or module_name] = module_name
            if module_name in RISKY_MODULE_IMPORTS:
                risk_info = RISKY_MODULE_IMPORTS[module_name]
                # Try to get the source line for context
                try:
                    code_snippet = ast.get_source_segment(self._source_code, node) or f"import {module_name}"
                except Exception:
                    code_snippet = f"import {module_name}"
                self._add_finding(node, risk_info, code_snippet)
        self.generic_visit(node) # Continue visiting child nodes if any

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Visit ImportFrom nodes."""
        module_name = node.module
        if module_name is None: # e.g., from . import foo
            self.generic_visit(node)
            return

        # Check if importing the module itself is risky
        if module_name in RISKY_MODULE_IMPORTS:
            risk_info = RISKY_MODULE_IMPORTS[module_name]
            try:
                code_snippet = ast.get_source_segment(self._source_code, node) or f"from {module_name} import ..."
            except Exception:
                code_snippet = f"from {module_name} import ..."
            self._add_finding(node, risk_info, code_snippet)

        # Store imported names with their original module source
        for alias in node.names:
            imported_name = alias.name
            full_name = f"{module_name}.{imported_name}"
            # Store alias if present, otherwise alias is the imported name
            self.imported_names[alias.asname or imported_name] = full_name

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Visit Call nodes to check for risky function calls."""
        func_name = None
        # Try to reconstruct the full function name (e.g., os.system, requests.get)
        if isinstance(node.func, ast.Name):
            # Direct function call like eval(...) or a locally defined alias
            func_name = node.func.id
            # Resolve if it's an alias from an import
            if func_name in self.imported_names:
                 # e.g. import pickle as p; p.load() -> func_name 'p' resolves to 'pickle.load'
                 # This basic resolution might not be perfect for complex cases
                 original_name = self.imported_names[func_name]
                 # Check if the resolved name itself is a risky call pattern
                 if original_name in RISKY_CALLS:
                     func_name = original_name
                 # If not a direct risky call, it might be a risky module function call
                 # e.g. import requests as r; r.get() -> original_name 'requests'
                 # We don't have 'requests.get' in RISKY_CALLS, but 'requests' import is flagged
                 # For simplicity, we rely on import flagging for now.

        elif isinstance(node.func, ast.Attribute):
            # Attribute call like os.system(...) or requests.get(...)
            try:
                # Try to get the base object name (e.g., 'os' in os.system)
                base_name = ""
                curr = node.func.value
                while isinstance(curr, ast.Attribute):
                    base_name = f"{curr.attr}.{base_name}" if base_name else curr.attr
                    curr = curr.value
                if isinstance(curr, ast.Name):
                    base_name = f"{curr.id}.{base_name}" if base_name else curr.id

                # Resolve base if it's an alias
                parts = base_name.split('.', 1)
                if parts[0] in self.imported_names:
                   resolved_base = self.imported_names[parts[0]]
                   # Handle cases like 'import os.path as p; p.join()' vs 'import os as o; o.path.join()'
                   # This simple alias check might need refinement for complex scenarios.
                   # For now, assume simple alias replacement if the base matches an alias.
                   base_name = resolved_base + (f".{parts[1]}" if len(parts) > 1 else "")


                # Full function name including attribute
                func_name = f"{base_name}.{node.func.attr}"

            except AttributeError:
                func_name = None # Complex expression, hard to resolve statically

        if func_name:
            # Check against direct risky calls (e.g., 'eval', 'os.system')
            if func_name in RISKY_CALLS:
                risk_info = RISKY_CALLS[func_name]
                try:
                    code_snippet = ast.get_source_segment(self._source_code, node) or f"{func_name}(...)"
                except Exception:
                     code_snippet = f"{func_name}(...)"
                self._add_finding(node, risk_info, code_snippet)
            else:
                # Check if the call belongs to a risky module (e.g., requests.get)
                # This relies on the module import having already been flagged.
                # More granular checks could be added here if needed.
                module_part = func_name.split('.')[0]
                if module_part in RISKY_MODULE_IMPORTS:
                    # We already flagged the import, but could add context here if desired
                    pass

        self.generic_visit(node) # Continue visiting child nodes

    def scan(self, code: str):
        """Parses the code and initiates the AST visit."""
        try:
            self._source_code = code # Store source for snippet extraction
            tree = ast.parse(code, filename=self.file_path)
            self.visit(tree)
        except SyntaxError as e:
            logging.error(f"Syntax error parsing {self.file_path}: {e}")
            # Add a finding for the syntax error itself? Maybe not for MVP.
        except Exception as e:
            logging.error(f"Error parsing AST for {self.file_path}: {e}")


def scan_file_ast(file_path: str) -> List[Dict[str, Any]]:
    """
    Reads a Python file, parses its AST, and scans for risky patterns.

    Args:
        file_path: Path to the Python file.

    Returns:
        A list of findings (dictionaries).
    """
    logging.info(f"Scanning file with AST: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return []
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return []

    visitor = AstScannerVisitor(file_path)
    visitor.scan(code)

    return visitor.findings

# Example Usage (for testing purposes)
if __name__ == '__main__':
    import tempfile
    import os

    # Create a dummy file with risky code
    dummy_code = """
import pickle
import os
import requests
import subprocess as sp
from socket import socket as sock

# This is risky
eval('print("evaluated")')

# Also risky
os.system('ls -l')

# ML related risk
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

# Network call
response = requests.get('https://example.com')

# Subprocess
sp.run(['echo', 'hello'])

# Socket usage
s = sock()

def harmless():
    pass

class MyClass:
    def method(self):
        exec('print("executed in method")')

# Dill usage
try:
    import dill
    dill.loads(b'data')
except ImportError:
    pass

# Ctypes usage
try:
    import ctypes
    libc = ctypes.CDLL(None)
except Exception:
    pass

# Importlib usage
import importlib
mod = importlib.import_module('sys')

# Shelve usage
import shelve
d = shelve.open('test_shelf')
d.close()

# Compile usage
code_obj = compile('x = 1', '<string>', 'exec')
"""

    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py', encoding='utf-8') as tmp_file:
        tmp_file.write(dummy_code)
        tmp_file_path = tmp_file.name

    print(f"Scanning dummy file: {tmp_file_path}")
    findings = scan_file_ast(tmp_file_path)
    print("\nFindings:")
    for finding in findings:
        print(f"- {finding['type']} ({finding['severity']}) at {finding['file_path']}:{finding['line_number']}")
        print(f"  Message: {finding['message']}")
        print(f"  Snippet: {finding['code_snippet']}")


    # Clean up the temporary file
    os.remove(tmp_file_path)
    print(f"\nCleaned up dummy file: {tmp_file_path}")

