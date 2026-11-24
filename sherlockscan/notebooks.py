"""Extract Python code from notebook JSON without invoking a kernel."""

from __future__ import annotations

import io
import json
import tokenize


def code_cells(data):
    notebook = json.loads(data)
    if not isinstance(notebook, dict) or notebook.get("nbformat") != 4:
        raise ValueError("Expected a version 4 Jupyter notebook")
    metadata = notebook.get("metadata", {})
    language = metadata.get("language_info", {}).get("name") or metadata.get("kernelspec", {}).get("language")
    if language and (not isinstance(language, str) or language.lower() != "python"):
        raise ValueError("Notebook declares a non-Python kernel")
    cells = notebook.get("cells")
    if not isinstance(cells, list):
        raise ValueError("Notebook cells must be a list")
    for index, cell in enumerate(cells, 1):
        if not isinstance(cell, dict):
            raise ValueError("Malformed notebook cell")
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", "")
        if isinstance(source, list) and all(isinstance(line, str) for line in source):
            source = "".join(source)
        if not isinstance(source, str):
            raise ValueError("Notebook code cell source must be text")
        yield index, source


def prepare_cell(source):
    """Replace IPython lines with Python placeholders while retaining line numbers."""
    string_lines = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.STRING and token.start[0] < token.end[0]:
                string_lines.update(range(token.start[0] + 1, token.end[0] + 1))
    except (tokenize.TokenError, IndentationError):
        # Let the AST parser report an incomplete scan if the remaining code is invalid.
        pass
    lines = source.splitlines(keepends=True)
    directives = []
    for idx, line in enumerate(lines):
        if idx + 1 in string_lines:
            continue
        stripped = line.lstrip()
        if stripped.startswith("%%"):
            directives.append((idx + 1, "cell magic"))
            return "", directives, True
        if stripped.startswith(("!", "%")):
            if stripped.startswith("!") or stripped.split()[0] in {"%run", "%pip", "%conda"}:
                directives.append(
                    (idx + 1, "shell command" if stripped.startswith("!") else stripped.split()[0])
                )
            indent = line[: len(line) - len(stripped)]
            lines[idx] = indent + "pass\n"
    return "".join(lines), directives, False
