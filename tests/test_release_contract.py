"""Release gates and errors must not be mistaken for safe/complete verdicts."""

import io
import json
from pathlib import Path
from unittest.mock import patch
import pytest
import yaml
from typer.testing import CliRunner
from sherlockscan.cli import app
from sherlockscan.engine import scan_package
from sherlockscan.ingestor import Limits, ingest
from sherlockscan.scanner.deps import build_sbom


@pytest.fixture
def project(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="demo"\nversion="1"\ndependencies=[]')
    (tmp_path / "main.py").write_text("answer=42")
    return tmp_path


def test_sbom_does_not_use_host_installed_versions():
    with patch(
        "sherlockscan.scanner.deps.importlib_metadata.version",
        side_effect=AssertionError("host metadata is unrelated"),
    ):
        sbom = build_sbom("demo", "1", ['requests>=2; python_version > "3"'])
    assert "version" not in sbom["components"][0]
    assert "requests>=2" in sbom["components"][0]["properties"][0]["value"]


def test_missing_and_malformed_metadata(project):
    (project / "pyproject.toml").unlink()
    assert scan_package(str(project))["status"] == "INCOMPLETE"
    (project / "pyproject.toml").write_text('[project]\nname="demo"\nversion="1"\ndependencies=["???"]')
    with pytest.raises(ValueError):
        scan_package(str(project))


def test_invalid_dependency_policy(project, tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    (config / "risk_patterns.yaml").write_text("regex_patterns: []")
    (config / "approved_packages.yaml").write_text("blocklist: wrong")
    with pytest.raises(Exception):
        scan_package(str(project), config_dir=config)


def test_invalid_regex_fails_before_download(project):
    (project / "risk_patterns.yaml").write_text('regex_patterns:\n  - pattern: "["')
    with patch("sherlockscan.engine.ingest", side_effect=AssertionError("must validate before ingestion")):
        with pytest.raises(Exception) as exc:
            scan_package("demo", config_dir=project)
    assert not isinstance(exc.value, AssertionError)


def test_symlink_directory_is_incomplete_and_not_followed(project, tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    (outside / "evil.py").write_text("eval(data)")
    try:
        (project / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("OS account cannot create symlinks")
    report = scan_package(str(project))
    assert report["exit_code"] == 20 and not report["findings"]


def test_no_deobfuscation_and_oversized_sources_are_visible(project):
    assert scan_package(str(project), deobfuscation=False)["exit_code"] == 20
    (project / "main.py").write_text("#" + "a" * (2 * 1024 * 1024))
    assert scan_package(str(project))["exit_code"] == 20


def test_local_project_metadata_overrides_stale_generated_metadata(project):
    info = project / "old.egg-info"
    info.mkdir()
    (info / "PKG-INFO").write_text(
        "Metadata-Version: 2.4\nName: stale\nVersion: 0\nDynamic: requires-dist\n\n"
    )
    report = scan_package(str(project))
    assert report["package_name"] == "demo"
    assert report["metadata_source"] == "pyproject.toml"
    assert report["exit_code"] == 0


def test_huge_literal_budget_and_policy_precedence(project):
    (project / "main.py").write_text("eval(payload)\nblob=" + repr("A" * 70000))
    report = scan_package(str(project), fail_on="HIGH")
    assert report["exit_code"] == 20
    assert report["actionable_summary"]["by_severity"]["HIGH"] >= 1


def test_do_not_load_suppressions_from_untrusted_target(project):
    (project / "main.py").write_text("eval(payload)")
    (project / ".sherlockscan.yaml").write_text("suppressions: [everything]")
    assert scan_package(str(project), fail_on="HIGH")["exit_code"] == 10


def test_output_write_failure_is_error(project):
    result = CliRunner().invoke(app, ["scan", str(project), "-o", str(project)])
    assert result.exit_code == 30


def test_exception_does_not_echo_secret(project):
    with patch("sherlockscan.cli.scan_package", side_effect=ValueError("secret_value_123")):
        result = CliRunner().invoke(app, ["scan", str(project)])
    assert result.exit_code == 30 and "secret_value_123" not in result.output


def test_no_publish_on_push_and_manual_review_required():
    root = Path(__file__).resolve().parents[1]
    # BaseLoader preserves YAML's 'on' as a string, unlike YAML 1.1 booleans.
    workflow = yaml.load((root / ".github/workflows/publish.yml").read_text(), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    assert inputs["release_reviewed"]["default"] == "false"
    assert "inputs.release_reviewed" in workflow["jobs"]["build"]["if"]
    assert workflow["jobs"]["publish-to-pypi"]["needs"] == "build"
