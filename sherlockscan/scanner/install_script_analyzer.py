#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/scanner/install_script_analyzer.py

import ast
import logging
import os
import toml # Requires 'pip install toml'
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define risky elements specific to setup.py context
# Re-use categories/severities where applicable, maybe increase severity
SETUP_PY_RISKS = {
    "os.system": {"type": "Install Script Execution", "severity": "CRITICAL", "message": "Execution of 'os.system' found in setup.py. Runs arbitrary shell commands during setup."},
    "os.popen": {"type": "Install Script Execution", "severity": "CRITICAL", "message": "Execution of 'os.popen' found in setup.py. Runs arbitrary shell commands during setup."},
    "subprocess": {"type": "Install Script Execution", "severity": "HIGH", "message": "Use of 'subprocess' module found in setup.py. Allows running external commands during setup."},
    "eval": {"type": "Install Script Execution", "severity": "CRITICAL", "message": "Use of 'eval' found in setup.py. Executes arbitrary strings as code during setup."},
    "exec": {"type": "Install Script Execution", "severity": "CRITICAL", "message": "Use of 'exec' found in setup.py. Executes arbitrary code blocks during setup."},
    "network": {"type": "Install Script Network", "severity": "HIGH", "message": "Network module (e.g., requests, socket, urllib) usage detected in setup.py. Potential data exfiltration or downloading malicious code during setup."},
    "compile": {"type": "Install Script Execution", "severity": "HIGH", "message": "Use of 'compile' found in setup.py. Can compile arbitrary strings for execution."},
    # Could add file operations checks here later (e.g., writing outside package dir)
}

# Modules considered risky if imported/used in setup.py
SETUP_PY_RISKY_MODULES = {
    "subprocess": SETUP_PY_RISKS["subprocess"],
    "socket": SETUP_PY_RISKS["network"],
    "requests": SETUP_PY_RISKS["network"],
    "urllib": SETUP_PY_RISKS["network"],
    "http.client": SETUP_PY_RISKS["network"],
    "ftplib": SETUP_PY_RISKS["network"],
    "smtplib": SETUP_PY_RISKS["network"],
    # os module itself isn't flagged, only specific risky calls like os.system
}

# Specific function calls considered risky in setup.py
SETUP_PY_RISKY_CALLS = {
    "eval": SETUP_PY_RISKS["eval"],
    "exec": SETUP_PY_RISKS["exec"],
    "compile": SETUP_PY_RISKS["compile"],
    "os.system": SETUP_PY_RISKS["os.system"],
    "os.popen": SETUP_PY_RISKS["os.popen"],
    "subprocess.run": SETUP_PY_RISKS["subprocess"],
    "subprocess.call": SETUP_PY_RISKS["subprocess"],
    "subprocess.check_call": SETUP_PY_RISKS["subprocess"],
    "subprocess.check_output": SETUP_PY_RISKS["subprocess"],
    "subprocess.Popen": SETUP_PY_RISKS["subprocess"],
    # Network calls could be added, but module import is often enough warning
}


class SetupPyVisitor(ast.NodeVisitor):
    """
    Visits nodes in a setup.py AST to find risky patterns specific to setup scripts.
    Inherits basic structure from AstScannerVisitor but uses setup-specific risks.
    """
    def __init__(self, file_path: str):
        self.findings: List[Dict[str, Any]] = []
        self.file_path: str = file_path
        self.imported_names: Dict[str, str] = {} # alias -> original_name
        self._source_code: Optional[str] = None # To store source code for snippets

    def _add_finding(self, node: ast.AST, risk_info: Dict, code_snippet: str = "N/A"):
        """Helper method to add a finding."""
        finding = {
            "type": risk_info["type"],
            "severity": risk_info["severity"],
            "file_path": self.file_path,
            "line_number": node.lineno,
            "code_snippet": code_snippet,
            "message": risk_info["message"]
        }
        # Avoid duplicate findings for the same issue on the same line
        # Simple check based on line number and type for now
        if not any(f['line_number'] == finding['line_number'] and f['type'] == finding['type'] for f in self.findings):
            self.findings.append(finding)
            logging.debug(f"Setup.py Finding Added: {finding}")

    def visit_Import(self, node: ast.Import):
        """Visit Import nodes."""
        for alias in node.names:
            module_name = alias.name
            self.imported_names[alias.asname or module_name] = module_name
            if module_name in SETUP_PY_RISKY_MODULES:
                risk_info = SETUP_PY_RISKY_MODULES[module_name]
                try:
                    code_snippet = ast.get_source_segment(self._source_code, node) if self._source_code else f"import {module_name}"
                except Exception: code_snippet = f"import {module_name}"
                self._add_finding(node, risk_info, code_snippet)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Visit ImportFrom nodes."""
        module_name = node.module
        if module_name is None:
            self.generic_visit(node)
            return

        if module_name in SETUP_PY_RISKY_MODULES:
            risk_info = SETUP_PY_RISKY_MODULES[module_name]
            try:
                code_snippet = ast.get_source_segment(self._source_code, node) if self._source_code else f"from {module_name} import ..."
            except Exception: code_snippet = f"from {module_name} import ..."
            self._add_finding(node, risk_info, code_snippet)

        for alias in node.names:
            imported_name = alias.name
            full_name = f"{module_name}.{imported_name}"
            self.imported_names[alias.asname or imported_name] = full_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Visit Call nodes to check for risky function calls."""
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.imported_names:
                 original_name = self.imported_names[func_name]
                 if original_name in SETUP_PY_RISKY_CALLS:
                     func_name = original_name # Resolved alias to risky call
                 # else: Could check if original_name is a module and func_name is just func part? Complex.
        elif isinstance(node.func, ast.Attribute):
            try:
                base_name = ""
                curr = node.func.value
                while isinstance(curr, ast.Attribute):
                    base_name = f"{curr.attr}.{base_name}" if base_name else curr.attr
                    curr = curr.value
                if isinstance(curr, ast.Name):
                    base_name = f"{curr.id}.{base_name}" if base_name else curr.id
                
                # Basic alias resolution for base
                parts = base_name.split('.', 1)
                if parts[0] in self.imported_names:
                   resolved_base = self.imported_names[parts[0]]
                   base_name = resolved_base + (f".{parts[1]}" if len(parts) > 1 else "")

                func_name = f"{base_name}.{node.func.attr}"
            except AttributeError: func_name = None

        if func_name and func_name in SETUP_PY_RISKY_CALLS:
            risk_info = SETUP_PY_RISKY_CALLS[func_name]
            try:
                 code_snippet = ast.get_source_segment(self._source_code, node) if self._source_code else f"{func_name}(...)"
            except Exception: code_snippet = f"{func_name}(...)"
            self._add_finding(node, risk_info, code_snippet)

        self.generic_visit(node)

    def scan(self, code: str):
        """Parses the code and initiates the AST visit."""
        try:
            self._source_code = code
            tree = ast.parse(code, filename=self.file_path)
            self.visit(tree)
        except SyntaxError as e:
            logging.error(f"Syntax error parsing {self.file_path}: {e}")
        except Exception as e:
            logging.error(f"Error parsing AST for {self.file_path}: {e}")


def scan_setup_py(file_path: str) -> List[Dict[str, Any]]:
    """
    Reads and scans a setup.py file using AST analysis for setup-specific risks.
    """
    logging.info(f"Scanning setup.py: {file_path}")
    findings: List[Dict[str, Any]] = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
    except Exception as e:
        logging.error(f"Error reading setup.py file {file_path}: {e}")
        return findings # Return empty list if file cannot be read

    visitor = SetupPyVisitor(file_path)
    visitor.scan(code)
    return visitor.findings


def scan_pyproject_toml(file_path: str) -> List[Dict[str, Any]]:
    """
    Reads and scans a pyproject.toml file for potentially risky configurations.
    """
    logging.info(f"Scanning pyproject.toml: {file_path}")
    findings: List[Dict[str, Any]] = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = toml.load(f)
    except FileNotFoundError:
        logging.error(f"pyproject.toml not found: {file_path}")
        return findings
    except toml.TomlDecodeError as e:
        logging.error(f"Error decoding TOML file {file_path}: {e}")
        return findings
    except Exception as e:
        logging.error(f"Error reading pyproject.toml file {file_path}: {e}")
        return findings

    # Check for custom build backend specified via backend-path
    build_system = data.get("build-system", {})
    backend_path = build_system.get("backend-path")
    if backend_path:
        findings.append({
            "type": "Install Script Custom Build",
            "severity": "INFO", # Informational, as custom backends are legitimate
            "file_path": file_path,
            "line_number": None, # TOML doesn't have clear line numbers for values easily
            "code_snippet": f"build-system.backend-path = {backend_path}",
            "message": "Custom build backend specified via 'backend-path'. Requires manual review of the backend code if source is untrusted."
        })

    # Check for potentially suspicious build requirements
    build_requires = build_system.get("requires", [])
    # Define suspicious patterns or packages if needed - for MVP, just note custom backend path
    # Example: if any('some-suspicious-build-tool' in req for req in build_requires): ...

    # Check for custom commands (e.g., via setuptools integration)
    tool_table = data.get("tool", {})
    setuptools_config = tool_table.get("setuptools", {})
    cmdclass = setuptools_config.get("cmdclass")
    if cmdclass:
         findings.append({
            "type": "Install Script Custom Command",
            "severity": "MEDIUM", # Custom commands are more directly risky than backend path
            "file_path": file_path,
            "line_number": None,
            "code_snippet": f"tool.setuptools.cmdclass = {cmdclass}",
            "message": "Custom build commands defined via 'tool.setuptools.cmdclass'. These commands execute Python code during build/install and require review."
        })
        
    # Add more checks here for other build systems (flit, poetry) if needed later

    return findings


def scan_install_scripts(package_dir: str) -> List[Dict[str, Any]]:
    """
    Finds and scans setup.py and pyproject.toml within a package directory.

    Args:
        package_dir: The root directory of the extracted package.

    Returns:
        A list of findings from both files.
    """
    all_findings: List[Dict[str, Any]] = []
    
    setup_py_path = os.path.join(package_dir, "setup.py")
    pyproject_toml_path = os.path.join(package_dir, "pyproject.toml")

    if os.path.exists(setup_py_path):
        all_findings.extend(scan_setup_py(setup_py_path))
    else:
        logging.info(f"No setup.py found in {package_dir}")

    if os.path.exists(pyproject_toml_path):
        all_findings.extend(scan_pyproject_toml(pyproject_toml_path))
    else:
        logging.info(f"No pyproject.toml found in {package_dir}")
        
    return all_findings


# Example Usage (for testing purposes)
if __name__ == '__main__':
    import tempfile
    import shutil

    # Create dummy setup.py content
    dummy_setup_py_content = """
import os
from setuptools import setup
import requests # Risky import

# Risky command execution
os.system('echo "Running risky command during setup!"')

setup(
    name='dummy_package',
    version='0.1',
    description='A package with a risky setup.py',
    # Another risky execution
    author_email=eval("'author' + '@example.com'"),
)

# Download something?
try:
    requests.get("http://malicious.example.com/setup_ping")
except Exception:
    pass
"""

    # Create dummy pyproject.toml content
    dummy_pyproject_toml_content = """
[build-system]
requires = ["setuptools>=42", "wheel", "suspicious-build-dep"]
build-backend = "setuptools.build_meta"
# backend-path = ["."] # Example of custom backend path

[tool.setuptools.cmdclass]
build_py = "custom_build:BuildPyCommand" # Example of custom command
"""

    # Create temporary directory structure
    temp_dir = tempfile.mkdtemp()
    print(f"Created temporary directory: {temp_dir}")
    
    setup_py_path = os.path.join(temp_dir, "setup.py")
    pyproject_toml_path = os.path.join(temp_dir, "pyproject.toml")

    with open(setup_py_path, 'w', encoding='utf-8') as f:
        f.write(dummy_setup_py_content)
    with open(pyproject_toml_path, 'w', encoding='utf-8') as f:
        f.write(dummy_pyproject_toml_content)

    print(f"\nScanning install scripts in: {temp_dir}")
    
    findings = scan_install_scripts(temp_dir)
    
    print("\nFindings:")
    if findings:
        for finding in findings:
            print(f"- {finding['type']} ({finding['severity']}) at {os.path.basename(finding['file_path'])}:{finding['line_number'] or 'N/A'}")
            print(f"  Message: {finding['message']}")
            print(f"  Snippet: {finding['code_snippet']}")
    else:
        print("No findings.")

    # Clean up temporary directory
    try:
        shutil.rmtree(temp_dir)
        print(f"\nCleaned up temporary directory: {temp_dir}")
    except Exception as e:
        print(f"\nError cleaning up temp directory {temp_dir}: {e}")


