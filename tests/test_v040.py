import hashlib
import io
import json
from pathlib import Path

import jsonschema
from packaging.tags import Tag
from typer.testing import CliRunner

from sherlockscan.cli import app
from sherlockscan.engine import scan_package
from sherlockscan.ingestor import fetch_pypi
from sherlockscan.reporting import render
from sherlockscan.scanner.deps import build_sbom


def project(path, version, dependencies=(), source="pass"):
    path.mkdir()
    (path / "pyproject.toml").write_text(
        f'[project]\nname="demo"\nversion="{version}"\ndependencies={json.dumps(list(dependencies))}\n',
        encoding="utf-8",
    )
    (path / "module.py").write_text(source, encoding="utf-8")
    return path


def notebook(path, cells, language="python"):
    path.write_text(
        json.dumps({"nbformat": 4, "metadata": {"kernelspec": {"language": language}}, "cells": cells}),
        encoding="utf-8",
    )
    return path


def test_notebook_code_cells_and_locations(tmp_path):
    path = notebook(
        tmp_path / "analysis.ipynb",
        [
            {"cell_type": "markdown", "source": "exec('markdown')"},
            {
                "cell_type": "code",
                "source": ["# Setup\n", "!echo example\n", "eval('2 + 2')"],
                "outputs": [{"text": "exec('output')"}],
            },
            {"cell_type": "code", "source": "eval('2 + 2')"},
        ],
    )
    report = scan_package(path)
    assert report["exit_code"] == 0
    assert {
        (f["cell_index"], f["line_number"]) for f in report["findings"] if f["rule_id"] == "SHLK-EXEC"
    } == {(2, 3), (3, 1)}
    assert sum(f["rule_id"] == "SHLK-NOTEBOOK" for f in report["findings"]) == 1
    assert all(f["execution_context"] == "NOTEBOOK_CELL" for f in report["findings"])
    assert len({f["fingerprint"] for f in report["findings"]}) == len(report["findings"])
    rendered = json.loads(render(report, "sarif"))
    schema = Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json"
    jsonschema.Draft7Validator(json.loads(schema.read_text(encoding="utf-8"))).validate(rendered)
    for result in rendered["runs"][0]["results"]:
        assert "cell_line" in result["properties"]
        assert "region" not in result["locations"][0]["physicalLocation"]
    assert "cell 2, line 3" in render(report, "html")


def test_notebook_reports_uninspected_cells(tmp_path):
    path = notebook(
        tmp_path / "analysis.ipynb",
        [
            {"cell_type": "code", "source": "%%bash\necho example"},
            {"cell_type": "code", "source": "if"},
            {"cell_type": "code", "source": "eval('1')"},
        ],
    )
    report = scan_package(path)
    assert report["exit_code"] == 20
    assert any("cell 1" in message for message in report["coverage"]["limitations"])
    assert any("cell 2" in message for message in report["coverage"]["limitations"])
    assert any(f.get("cell_index") == 3 for f in report["findings"])


def test_notebook_magics_inside_strings_and_non_python_kernel(tmp_path):
    path = notebook(
        tmp_path / "analysis.ipynb",
        [{"cell_type": "code", "source": "notes = '''examples\n!echo example\n%%bash\n'''\npass"}],
    )
    result = scan_package(path)
    assert result["exit_code"] == 0
    assert all(f["rule_id"] != "SHLK-NOTEBOOK" for f in result["findings"])
    notebook(path, [{"cell_type": "code", "source": "eval('1')"}], language="julia")
    assert scan_package(path)["exit_code"] == 20


def test_notebook_in_wheel(tmp_path):
    from zipfile import ZipFile

    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    path = notebook(tmp_path / "example.ipynb", [{"cell_type": "code", "source": "eval('2 + 2')"}])
    with ZipFile(wheel, "w") as archive:
        archive.writestr("demo-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n")
        archive.write(path, "demo/example.ipynb")
    assert any(f["file_path"] == "demo/example.ipynb" for f in scan_package(wheel)["findings"])


def test_exact_fingerprint_suppression_for_repeated_redacted_findings(tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    (config / "risk_patterns.yaml").write_text(
        "regex_patterns:\n- name: Example Key\n  severity: HIGH\n  pattern: fake-[a-z]+\n", encoding="utf-8"
    )
    root = project(tmp_path / "tree", "1", source="# fake-aaaa and fake-bbbb\n# fake-cccc")
    report = scan_package(root, config_dir=config)
    matches = [f for f in report["findings"] if f["rule_id"].startswith("SHLK-SECRET")]
    assert len(matches) == len({f["fingerprint"] for f in matches}) == 3
    suppression = tmp_path / "suppressions.yaml"
    suppression.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "rule_id": matches[0]["rule_id"],
                        "fingerprint": matches[0]["fingerprint"],
                        "reason": "Reviewed fixture",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = scan_package(root, config_dir=config, suppressions=suppression, fail_on="HIGH")
    assert result["exit_code"] == 10
    assert sum(f["suppressed"] for f in result["findings"]) == 1
    assert "fake-aaaa" not in render(result, "html")


def test_typo_hints_are_opt_in_and_canonicalized(tmp_path):
    root = project(tmp_path / "tree", "1", ["nupmy", "scikit_learn", "torch"])
    assert not scan_package(root)["findings"]
    result = scan_package(root, check_dependency_names=True, fail_on="HIGH")
    hints = [f for f in result["findings"] if f["rule_id"] == "SHLK-TYPO"]
    assert [(f["evidence"]["dependency_name"], tuple(f["evidence"]["similar_names"])) for f in hints] == [
        ("nupmy", ("numpy",))
    ]
    assert result["exit_code"] == 0


def test_sbom_merges_component_declarations_and_links_direct_dependencies():
    result = build_sbom("demo", "1", ["requests>=2", "Requests[socks]>=2", "requests>=2"])
    assert len(result["components"]) == 1
    component = result["components"][0]
    assert len(component["properties"]) == 2
    assert "version" not in component
    assert result["dependencies"] == [
        {"ref": result["metadata"]["component"]["bom-ref"], "dependsOn": [component["bom-ref"]]}
    ]


def test_diff_reports_changes_and_ignores_simple_line_moves(tmp_path):
    old = project(
        tmp_path / "before", "1", ["requests>=2"], source="eval('2 + 2')\ncompile(code, 'f', 'exec')"
    )
    new = project(
        tmp_path / "after",
        "2",
        ["requests>=3"],
        source="\n\neval('2 + 2')\nimport pickle\npickle.loads(blob)",
    )
    result = CliRunner().invoke(app, ["diff", str(old), str(new)])
    assert result.exit_code == 0, result.output
    comparison = json.loads(result.stdout)
    assert comparison["matched_findings"] == 1
    assert {f["rule_id"] for f in comparison["added_findings"]} == {"SHLK-IMPORT", "SHLK-PICKLE"}
    assert {f["rule_id"] for f in comparison["removed_findings"]} == {"SHLK-EXEC"}
    assert comparison["added_requirements"] == [{"extra": None, "requirement": "requests>=3"}]
    assert comparison["removed_requirements"] == [{"extra": None, "requirement": "requests>=2"}]
    (new / "module.py").write_text("if", encoding="utf-8")
    result = CliRunner().invoke(app, ["diff", str(old), str(new)])
    assert result.exit_code == 20
    assert json.loads(result.stdout)["status"] == "INCOMPLETE"


def test_html_does_not_treat_project_name_as_markup(tmp_path):
    path = project(tmp_path / "demo", "1")
    (path / "pyproject.toml").write_text(
        '[project]\nname="<script>alert(1)</script>"\nversion="1"\n', encoding="utf-8"
    )
    result = CliRunner().invoke(app, ["scan", str(path), "--format", "html"])
    assert result.exit_code == 0
    assert "<script>" not in result.output
    assert "&lt;script&gt;" in result.output


def test_missing_local_file_error(tmp_path):
    result = CliRunner().invoke(app, ["scan", str(tmp_path / "missing.whl")])
    assert result.exit_code == 30
    assert "Local target does not exist" in result.output


def test_model_provenance_and_unresolved_option_redaction(tmp_path):
    path = project(
        tmp_path / "tree",
        "1",
        source=(
            "import torch as t\n"
            "from huggingface_hub import snapshot_download as snapshot\n"
            "t.jit.load(model_path)\n"
            "t.hub.load(repo, model_name)\n"
            "snapshot(repo, revision='main')\n"
            "snapshot(repo, local_files_only=True)\n"
            "snapshot(repo, revision='" + "0" * 40 + "')\n"
            "t.load(model_path, pickle_module=b'private-data')\n"
        ),
    )
    report = scan_package(path)
    relevant = {
        f["line_number"]: f["rule_id"]
        for f in report["findings"]
        if f["rule_id"] in {"SHLK-PICKLE", "SHLK-MODEL-SOURCE", "SHLK-TORCH"}
    }
    assert relevant == {3: "SHLK-PICKLE", 4: "SHLK-MODEL-SOURCE", 5: "SHLK-MODEL-SOURCE", 8: "SHLK-TORCH"}
    assert "private-data" not in render(report)


def test_wheel_tag_preference_and_exact_cross_platform_selection(tmp_path, monkeypatch):
    preferred = "demo-1.0-cp312-cp312-win_amd64.whl"
    other = "demo-1.0-cp312-abi3-win_amd64.whl"
    foreign = "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    blob = b"fake CDN artifact bytes"
    files = [
        {
            "packagetype": "bdist_wheel",
            "filename": name,
            "url": f"https://files.pythonhosted.org/{name}",
            "digests": {"sha256": hashlib.sha256(blob).hexdigest()},
            "size": len(blob),
        }
        for name in (other, foreign, preferred)
    ]
    manifest = json.dumps({"info": {"version": "1.0"}, "urls": files}).encode()

    class Response(io.BytesIO):
        def __init__(self, url):
            super().__init__(manifest if url.startswith("https://pypi.org/") else blob)
            self.url = url

        def geturl(self):
            return self.url

    monkeypatch.setattr("sherlockscan.ingestor.urlopen", lambda url, **kw: Response(url))
    monkeypatch.setattr(
        "sherlockscan.ingestor.sys_tags",
        lambda: [Tag("cp312", "cp312", "win_amd64"), Tag("cp312", "abi3", "win_amd64")],
    )
    assert fetch_pypi("demo==1.0", tmp_path / "picked")["filename"] == preferred
    assert fetch_pypi("demo==1.0", tmp_path / "explicit", artifact_filename=foreign)["filename"] == foreign
