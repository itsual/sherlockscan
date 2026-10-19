"""Static inspection and opt-in CI thresholds."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
import typer
from . import __version__
from .engine import scan_package
from .findings import DISCLAIMER, SEVERITIES
from .reporting import render

app = typer.Typer(add_completion=False, help="Static Python package risk inspection. " + DISCLAIMER)


@app.callback()
def main_callback():
    """Inspect potential risks without executing package code."""


@app.command()
def version():
    """Print scanner version."""
    typer.echo(__version__)


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@app.command()
def scan(
    package_target: str = typer.Argument(..., help="Directory, archive, PyPI name or name==version."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    format: str = typer.Option("md", "--format", "-f", help="md, json or sarif"),
    config_dir: Optional[Path] = typer.Option(None, "--config", "-c"),
    severity: str = typer.Option("INFO", "--severity", "-s", help="Display filter; does not affect policy."),
    include_tests: bool = typer.Option(False, "--include-tests"),
    sbom: Optional[Path] = typer.Option(None, "--sbom"),
    suppressions: Optional[Path] = typer.Option(
        None, "--suppressions", help="Explicit suppression file; never auto-load target policy."
    ),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on", help="Fail CI for active findings at this severity or above."
    ),
    no_deobfuscation: bool = typer.Option(False, "--no-deobfuscation"),
):
    """Exits: 0 complete, 10 policy failed, 20 incomplete, 30 error; invalid CLI options exit 2."""
    format, severity = format.lower(), severity.upper()
    fail_on = fail_on.upper() if fail_on else None
    if (
        format not in {"md", "json", "sarif"}
        or severity not in SEVERITIES
        or (fail_on and fail_on not in SEVERITIES)
    ):
        raise typer.BadParameter("Choose md/json/sarif and CRITICAL/HIGH/MEDIUM/LOW/INFO severities")
    try:
        report = scan_package(
            package_target,
            config_dir=config_dir,
            include_tests=include_tests,
            suppressions=suppressions,
            fail_on=fail_on,
            deobfuscation=not no_deobfuscation,
        )
        if output and sbom and output.resolve() == sbom.resolve():
            raise ValueError("Report and SBOM paths must differ")
        content = render(report, format, severity)
        if output:
            _write(output, content)
        else:
            typer.echo(content)
        if sbom:
            from .scanner.deps import build_sbom

            requirements = report["requirements"] + [
                r for group in report["optional_dependencies"].values() for r in group
            ]
            _write(
                sbom,
                json.dumps(
                    build_sbom(report["package_name"], report["package_version"], requirements), indent=2
                ),
            )
    except Exception as exc:
        typer.echo(
            f"Scanner error ({type(exc).__name__}). Check target, configuration, network and output permissions.",
            err=True,
        )
        raise typer.Exit(30)
    raise typer.Exit(report["exit_code"])


if __name__ == "__main__":
    app()
