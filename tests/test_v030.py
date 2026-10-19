"""Security and accuracy regressions for the artifact-based scan pipeline."""

import base64
import hashlib
import io
import json
import stat
import tarfile
import zipfile
import zlib
from datetime import date
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

from sherlockscan.cli import app
from sherlockscan.context_scanner import scan_source
from sherlockscan.deobfuscator import decode_literal
from sherlockscan.engine import scan_package
from sherlockscan.findings import DISCLAIMER
from sherlockscan.ingestor import Limits, fetch_pypi, read_archive, safe_name
from sherlockscan.policy import apply_suppressions, load_suppressions
from sherlockscan.reporting import render

META = b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n\n"


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="demo"\nversion="1.0"\ndependencies=[]\n')
    (root / "main.py").write_text("answer = 42\n")
    return root


def wheel(tmp_path, members=None):
    path = tmp_path / "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in (
            members or {"demo.dist-info/METADATA": META, "demo/__init__.py": b"answer=42"}
        ).items():
            archive.writestr(name, data)
    return path


@pytest.mark.parametrize(
    "name",
    [
        "../escape.py",
        "/absolute",
        "C:/escape",
        "C:escape",
        "..\\escape",
        "a/../b",
        "a/./b",
        "bad\x00name",
        "a./file",
    ],
)
def test_reject_cross_platform_paths(name):
    with pytest.raises(ValueError):
        safe_name(name)


@pytest.mark.parametrize("name", ["../escape.py", "/absolute", "C:/escape", "..\\escape"])
def test_archive_path_rejection(tmp_path, name):
    with pytest.raises(ValueError):
        read_archive(wheel(tmp_path, {name: b"bad"}))
    assert not (tmp_path.parent / "escape.py").exists()


def test_zip_link(tmp_path):
    path = tmp_path / "link.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, "../escape")
    with pytest.raises(ValueError):
        read_archive(path)


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_tar_special_members(tmp_path, kind):
    path = tmp_path / "bad.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("special")
        info.type = kind
        info.linkname = "../outside"
        archive.addfile(info)
    with pytest.raises(ValueError):
        read_archive(path)


@pytest.mark.parametrize(
    "limits", [Limits(member=10), Limits(total=10), Limits(count=1), Limits(download=10)]
)
def test_archive_limits(tmp_path, limits):
    with pytest.raises(ValueError):
        read_archive(wheel(tmp_path), limits)


def test_zip_compression_ratio(tmp_path):
    path = wheel(tmp_path, {"bomb": b"0" * 100000})
    with pytest.raises(ValueError):
        read_archive(path, Limits(ratio=5))


def test_duplicate_archive_paths(tmp_path):
    path = wheel(tmp_path, {"A.py": b"a=1", "a.py": b"a=2"})
    with pytest.raises(ValueError):
        read_archive(path)


def test_metadata_preserves_requirements(tmp_path):
    req = 'requests[socks]>=2; python_version >= "3.9"'
    path = wheel(
        tmp_path, {"demo.dist-info/METADATA": META.replace(b"\n\n", f"\nRequires-Dist: {req}\n\n".encode())}
    )
    pkg = read_archive(path)
    assert pkg.requirements == [req]
    assert pkg.artifact["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_ambiguous_wheel_metadata(tmp_path):
    with pytest.raises(ValueError):
        read_archive(wheel(tmp_path, {"a.dist-info/METADATA": META, "b.dist-info/METADATA": META}))


def test_static_scan_never_executes_build_or_imports(tmp_path):
    sentinel = tmp_path / "EXECUTED"
    dangerous = (
        f'from pathlib import Path\nPath({str(sentinel)!r}).touch()\nraise RuntimeError("do not execute")\n'
    )
    path = tmp_path / "demo.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, data in {
            "demo/PKG-INFO": META,
            "demo/setup.py": dangerous.encode(),
            "demo/demo/__init__.py": dangerous.encode(),
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    with patch("subprocess.run", side_effect=AssertionError("Subprocess forbidden")):
        report = scan_package(str(path))
    assert report["package_name"] == "demo"
    assert report["exit_code"] == 0
    assert not sentinel.exists()


def test_native_missing_and_dynamic_metadata_are_incomplete(tmp_path, project):
    (project / "native.so").write_bytes(b"binary")
    assert scan_package(str(project))["exit_code"] == 20
    report = scan_package(str(wheel(tmp_path, {"demo/a.py": b"pass"})))
    assert not report["coverage"]["complete"]
    (project / "pyproject.toml").write_text('[project]\nname="demo"\ndynamic=["version","dependencies"]')
    assert scan_package(str(project))["exit_code"] == 20


def test_invalid_python_is_not_clean(project):
    (project / "main.py").write_text("def broken(:\n")
    report = scan_package(str(project))
    assert report["exit_code"] == 20
    assert "SyntaxError" in " ".join(report["coverage"]["limitations"])


def test_pth_execution_and_legitimate_path_lines(tmp_path):
    path = wheel(
        tmp_path,
        {
            "demo.dist-info/METADATA": META,
            "demo.py": b"pass",
            "startup.pth": b"# comment\npackage_path\nimport helper\n",
        },
    )
    findings = scan_package(str(path))["findings"]
    assert len(findings) == 1 and findings[0]["rule_id"] == "SHLK-PTH"
    assert findings[0]["line_number"] == 3


@pytest.mark.parametrize(
    "source,rule,expected",
    [
        ("import pickle as p\np.load(f)", "SHLK-PICKLE", 1),
        ("from pickle import loads as load\nload(blob)", "SHLK-PICKLE", 1),
        ('import subprocess as sp\nsp.run(["tool"],shell=True)', "SHLK-SHELL", 1),
        ("import numpy as np\nnp.load(path, allow_pickle=False)", "SHLK-NUMPY", 0),
        ("import numpy as np\nnp.load(path, None, True)", "SHLK-NUMPY", 1),
        ("import numpy as np\nnp.load(path, **options)", "SHLK-NUMPY", 1),
        ("import torch\ntorch.load(path, weights_only=True)", "SHLK-TORCH", 0),
        ("import torch\ntorch.load(path, weights_only=False)", "SHLK-TORCH", 1),
        ("import torch\ntorch.load(path)", "SHLK-TORCH", 1),
        ("import pickle as p\ndef f(p):\n p.load(blob)", "SHLK-PICKLE", 0),
        ("import pickle as p\ndef f():\n p.load(blob)\n p=other", "SHLK-PICKLE", 0),
        ('def eval(x):\n return x\neval("hi")', "SHLK-EXEC", 0),
    ],
)
def test_aliases_and_loader_arguments(source, rule, expected):
    findings, _ = scan_source(source, "module.py")
    assert sum(f["rule_id"] == rule for f in findings) == expected


def test_version_aware_torch(project):
    (project / "main.py").write_text("import torch\ntorch.load(path)")
    (project / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\ndependencies=["torch>=2.6"]'
    )
    assert not any(f["rule_id"] == "SHLK-TORCH" for f in scan_package(str(project))["findings"])


def test_execution_contexts():
    findings, _ = scan_source('def f(x=eval("1")):\n exec(x)\nf()', "setup.py")
    assert [f["execution_context"] for f in findings] == ["SETUP_OR_BUILD_SCRIPT", "FUNCTION_OR_METHOD"]
    findings, _ = scan_source('eval("1")', "tests/a.py")
    assert findings[0]["execution_context"] == "TEST_OR_DOCS"


def test_common_cloud_client_is_not_blocked(project):
    (project / "main.py").write_text('import os\nimport requests\nkey=os.getenv("TOKEN")\n')
    report = scan_package(str(project), fail_on="HIGH")
    assert report["exit_code"] == 0
    assert report["correlations"]
    assert all(f["severity"] == "INFO" for f in report["findings"])


def test_bounded_decoding():
    payload = b"a" * 600 + b" SECRET_MARKER"
    encoded = base64.b64encode(zlib.compress(payload))
    decoded, limited = decode_literal(encoded)
    assert not limited and decoded[-1][1] == payload
    assert decoded[-1][0] == ["base64", "zlib"]
    assert decode_literal(zlib.compress(b"A" * 100000), max_bytes=1000)[1]
    assert decode_literal("A" * 70000)[1]


def test_decoded_matches_beyond_preview_and_redacts(project, tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    secret = "PRIVATE_TEST_TOKEN_DO_NOT_LOG"
    (config / "risk_patterns.yaml").write_text(
        yaml.safe_dump(
            {
                "settings": {"entropy_threshold": 10},
                "regex_patterns": [
                    {
                        "id": "CUSTOM",
                        "name": "Token",
                        "type": "Hardcoded Secret",
                        "pattern": secret,
                        "severity": "HIGH",
                    }
                ],
            }
        )
    )
    encoded = base64.b64encode(("a" * 600 + secret).encode()).decode()
    (project / "main.py").write_text(f"payload={encoded!r}\nkey={secret!r}\neval(key)")
    report = scan_package(str(project), config_dir=config)
    assert any(f["evidence"].get("decoded") for f in report["findings"])
    for format in ["json", "md", "sarif"]:
        assert secret not in render(report, format)
        assert encoded not in render(report, format)


def test_suppression_policy_and_display_filter_are_independent(project, tmp_path):
    (project / "main.py").write_text("eval(data)\n")
    report = scan_package(str(project), fail_on="HIGH")
    assert report["exit_code"] == 10
    assert json.loads(render(report, "json", "CRITICAL"))["findings"] == []
    suppression = tmp_path / "suppressions.yaml"
    suppression.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "rule_id": "SHLK-EXEC",
                        "path": "main.py",
                        "reason": "Reviewed expression evaluator",
                        "expires": "2099-01-01",
                    }
                ],
            }
        )
    )
    report = scan_package(str(project), fail_on="HIGH", suppressions=suppression)
    assert report["exit_code"] == 0 and report["findings"][0]["suppressed"]
    assert report["full_summary"]["total_findings"] == 1
    assert report["actionable_summary"]["total_findings"] == 0
    assert json.loads(render(report, "sarif"))["runs"][0]["results"][0]["suppressions"]
    entries = load_suppressions(suppression)
    entries[0]["expires"] = "2000-01-01"
    report["findings"][0]["suppressed"] = False
    assert apply_suppressions(report["findings"], entries, today=date(2026, 10, 19))
    assert not report["findings"][0]["suppressed"]


@pytest.mark.parametrize(
    "entry",
    [
        {"rule_id": "*", "path": "main.py", "reason": "bad"},
        {"rule_id": "SHLK-EXEC", "path": "**", "reason": "bad"},
        {"rule_id": "SHLK-EXEC", "path": "../outside", "reason": "bad"},
        {"rule_id": "SHLK-EXEC", "reason": "too broad"},
        {"rule_id": "SHLK-EXEC", "path": "main.py", "reason": ""},
    ],
)
def test_invalid_suppressions(tmp_path, entry):
    file = tmp_path / "bad.yaml"
    file.write_text(yaml.safe_dump({"schema_version": 1, "suppressions": [entry]}))
    with pytest.raises(ValueError):
        load_suppressions(file)


def test_exclusions_and_fingerprints(project):
    (project / "tests").mkdir()
    (project / "tests" / "fixture.py").write_text("eval(payload)")
    report = scan_package(str(project))
    assert not report["findings"] and report["coverage"]["excluded_files"]
    assert scan_package(str(project), include_tests=True)["findings"]
    (project / "main.py").write_text("eval(payload)")
    before = scan_package(str(project))["findings"][0]["fingerprint"]
    (project / "main.py").write_text("\n\neval(payload)")
    assert scan_package(str(project))["findings"][0]["fingerprint"] == before


def test_sarif_official_schema(project):
    import jsonschema

    (project / "main.py").write_text("eval(data)")
    schema_path = Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json"
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft7Validator(schema).validate(json.loads(render(scan_package(str(project)), "sarif")))


class Response(io.BytesIO):
    def __init__(self, value, url):
        super().__init__(value)
        self.url = url

    def geturl(self):
        return self.url


def test_registry_hash_and_no_execution(tmp_path):
    from packaging.tags import sys_tags

    tags = list(sys_tags())
    path = wheel(tmp_path)
    blob = path.read_bytes()
    item = {
        "filename": path.name,
        "packagetype": "bdist_wheel",
        "url": "https://files.pythonhosted.org/demo.whl",
        "digests": {"sha256": hashlib.sha256(blob).hexdigest()},
        "size": len(blob),
    }
    payload = json.dumps({"info": {"version": "1.0"}, "urls": [item]}).encode()

    def open_url(url, **kwargs):
        return Response(payload if "pypi.org/pypi/" in url else blob, url)

    with (
        patch("sherlockscan.ingestor.urlopen", side_effect=open_url),
        patch("sherlockscan.ingestor.sys_tags", return_value=tags),
        patch("subprocess.run", side_effect=AssertionError),
    ):
        report = scan_package("demo==1.0")
        assert report["package_version"] == "1.0"
        assert report["artifact"]["sha256"] == item["digests"]["sha256"]
    item["digests"]["sha256"] = "0" * 64
    payload = json.dumps({"info": {"version": "1.0"}, "urls": [item]}).encode()
    with (
        patch("sherlockscan.ingestor.urlopen", side_effect=open_url),
        pytest.raises(ValueError, match="SHA-256"),
    ):
        fetch_pypi("demo", tmp_path / "download")


@pytest.mark.parametrize("target", ["https://evil.test/x", "demo --index-url evil", "demo>=1"])
def test_reject_arbitrary_registry_arguments(tmp_path, target):
    with pytest.raises(ValueError):
        fetch_pypi(target, tmp_path / "download")
