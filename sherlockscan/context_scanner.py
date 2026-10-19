"""Conservative AST capability inspection with lexical scope and argument evidence."""

from __future__ import annotations

import ast
from pathlib import PurePosixPath
from .findings import make_finding

NETWORK = {"requests", "httpx", "aiohttp", "socket", "urllib", "http", "ftplib", "smtplib"}
IMPORTS = {"pickle", "dill", "shelve", "subprocess", "importlib", "ctypes", "joblib", "cloudpickle"}
DESERIALIZE = {
    "pickle.load",
    "pickle.loads",
    "dill.load",
    "dill.loads",
    "shelve.open",
    "joblib.load",
    "cloudpickle.loads",
}
PROCESS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
    "pty.spawn",
}


class Visitor(ast.NodeVisitor):
    def __init__(self, source, path, torch_default):
        self.source, self.path, self.torch_default = source, path, torch_default
        self.bindings = [{}]
        self.contexts = ["TOP_LEVEL_IMPORT"]
        self.findings = []

    def name(self, node):
        if isinstance(node, ast.Name):
            for bindings in reversed(self.bindings):
                if node.id in bindings:
                    return bindings[node.id] or "<shadowed>"
            return node.id
        if isinstance(node, ast.Attribute):
            return self.name(node.value) + "." + node.attr
        return "<dynamic>"

    def emit(self, kind, node, **kwargs):
        parts = PurePosixPath(self.path).parts
        context = self.contexts[-1]
        if any(p in {"tests", "test", "integration", "docs", "examples"} for p in parts):
            context = "TEST_OR_DOCS"
        elif PurePosixPath(self.path).name == "setup.py" and context == "TOP_LEVEL_IMPORT":
            context = "SETUP_OR_BUILD_SCRIPT"
        self.findings.append(
            make_finding(
                kind,
                self.path,
                node.lineno,
                ast.get_source_segment(self.source, node) or "",
                context=context,
                **kwargs,
            )
        )

    def visit_Import(self, node):
        for alias in node.names:
            self.bindings[-1][alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0]
            )
            root = alias.name.split(".")[0]
            if root in NETWORK | IMPORTS:
                self.emit(
                    "NETWORK" if root in NETWORK else "IMPORT",
                    node,
                    detail="Import only; no data flow is established.",
                )

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.bindings[-1][alias.asname or alias.name] = (
                f"{node.module}.{alias.name}" if not node.level else "<relative>"
            )
        root = (node.module or "").split(".")[0]
        if not node.level and root in NETWORK | IMPORTS:
            self.emit("NETWORK" if root in NETWORK else "IMPORT", node, detail="Import only.")

    def visit_FunctionDef(self, node):
        # Decorators, defaults and annotations execute in the enclosing scope.
        for item in node.decorator_list + node.args.defaults + [x for x in node.args.kw_defaults if x]:
            self.visit(item)
        self.bindings[-1][node.name] = None
        arguments = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        shadow = {arg.arg: None for arg in arguments}
        for arg in (node.args.vararg, node.args.kwarg):
            if arg:
                shadow[arg.arg] = None

        # Python determines locals for the whole function, not line by line.
        def local_names(items):
            for item in items:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    yield item.name
                    continue
                if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                    yield item.id
                yield from local_names(ast.iter_child_nodes(item))

        shadow.update({name: None for name in local_names(node.body)})
        self.bindings.append(shadow)
        self.contexts.append("FUNCTION_OR_METHOD")
        for item in node.body:
            self.visit(item)
        self.contexts.pop()
        self.bindings.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        for item in node.args.defaults + [x for x in node.args.kw_defaults if x]:
            self.visit(item)
        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        self.bindings.append({arg.arg: None for arg in args})
        self.contexts.append("FUNCTION_OR_METHOD")
        self.visit(node.body)
        self.contexts.pop()
        self.bindings.pop()

    def visit_ClassDef(self, node):
        for item in node.bases + node.decorator_list + [k.value for k in node.keywords]:
            self.visit(item)
        self.bindings[-1][node.name] = None
        self.bindings.append({})
        for item in node.body:
            self.visit(item)
        self.bindings.pop()

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            for item in ast.walk(target):
                if isinstance(item, ast.Name):
                    self.bindings[-1][item.id] = None

    def visit_Call(self, node):
        name = self.name(node.func)
        options = {k.arg: k.value for k in node.keywords}

        def option(key, position=None):
            value = options.get(key)
            if value is None and position is not None and len(node.args) > position:
                value = node.args[position]
            if value is None:
                return (
                    "unknown"
                    if None in options or any(isinstance(a, ast.Starred) for a in node.args)
                    else "omitted"
                )
            return value.value if isinstance(value, ast.Constant) else "unknown"

        evidence = {"resolved_call": name}
        if name in {"eval", "exec", "compile", "__import__"}:
            self.emit("EXEC", node, evidence=evidence)
        elif name in PROCESS:
            shell = option("shell")
            self.emit(
                "SHELL",
                node,
                severity="HIGH" if shell is True or name in {"os.system", "os.popen"} else "MEDIUM",
                evidence={**evidence, "shell": shell},
            )
        elif name in DESERIALIZE:
            self.emit("PICKLE", node, evidence=evidence)
        elif name == "torch.load":
            weights, pickle_module = option("weights_only"), option("pickle_module", 2)
            if weights is not True or pickle_module != "omitted":
                if not (weights == "omitted" and pickle_module == "omitted" and self.torch_default):
                    self.emit(
                        "TORCH",
                        node,
                        severity="HIGH" if weights is False else "MEDIUM",
                        detail="Omitted defaults depend on PyTorch version; unresolved values require review.",
                        evidence={**evidence, "weights_only": weights, "pickle_module": pickle_module},
                    )
        elif name == "numpy.load":
            allow = option("allow_pickle", 2)
            if allow is True or allow == "unknown":
                self.emit(
                    "NUMPY",
                    node,
                    severity="HIGH" if allow is True else "MEDIUM",
                    evidence={**evidence, "allow_pickle": allow},
                )
        elif name in {"os.getenv", "os.environ.get"}:
            self.emit("ENV", node, evidence=evidence)
        elif name.split(".")[0] in NETWORK:
            self.emit("NETWORK", node, severity="LOW", evidence=evidence)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if isinstance(node.ctx, ast.Load) and self.name(node) == "os.environ":
            self.emit("ENV", node, evidence={"resolved_attribute": "os.environ"})
        self.generic_visit(node)


def scan_source(source, path, *, torch_default=False):
    tree = ast.parse(source, filename=path)
    visitor = Visitor(source, path, torch_default)
    visitor.visit(tree)
    return visitor.findings, tree
