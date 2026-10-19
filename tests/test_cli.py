"""CLI contracts tested on real local artifacts rather than mocked internal calls."""

import json
import pytest
from typer.testing import CliRunner
from sherlockscan.cli import app


@pytest.fixture
def package(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="demo"\nversion="1"\ndependencies=[]')
    (tmp_path / "main.py").write_text("eval(payload)")
    return tmp_path


@pytest.mark.parametrize("format", ["json", "md", "sarif"])
def test_reports(package, format):
    result = CliRunner().invoke(app, ["scan", str(package), "-f", format])
    assert result.exit_code == 0, result.output
    if format != "md":
        json.loads(result.stdout)
    assert "does not prove" in result.stdout


def test_policy_uses_all_findings(package):
    result = CliRunner().invoke(
        app, ["scan", str(package), "-f", "json", "-s", "CRITICAL", "--fail-on", "HIGH"]
    )
    assert result.exit_code == 10
    assert json.loads(result.stdout)["findings"] == []


def test_invalid_config_and_cli(package):
    result = CliRunner().invoke(app, ["scan", str(package), "--format", "xml"])
    assert result.exit_code == 2
    (package / "risk_patterns.yaml").write_text("regex_patterns: [broken")
    result = CliRunner().invoke(app, ["scan", str(package), "-c", str(package)])
    assert result.exit_code == 30


def test_output_and_sbom(package, tmp_path):
    output = tmp_path / "output" / "report.json"
    sbom = tmp_path / "output" / "sbom.json"
    result = CliRunner().invoke(
        app, ["scan", str(package), "-f", "json", "-o", str(output), "--sbom", str(sbom)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["package_name"] == "demo"
    assert json.loads(sbom.read_text())["bomFormat"] == "CycloneDX"


def test_parse_error_exit(package):
    (package / "main.py").write_text("def invalid(:")
    result = CliRunner().invoke(app, ["scan", str(package), "-f", "json"])
    assert result.exit_code == 20
    assert json.loads(result.stdout)["status"] == "INCOMPLETE"
