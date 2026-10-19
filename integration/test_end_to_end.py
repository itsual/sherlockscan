"""Package artifact and CLI integration, including startup/build side effects."""

import json
import zipfile
from typer.testing import CliRunner
from sherlockscan.cli import app


def test_wheel_scan_without_host_metadata(tmp_path):
    wheel = tmp_path / "demo-1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "demo.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: demo\nVersion: 1\nRequires-Dist: forbidden>=2\n\n",
        )
        archive.writestr("demo/__init__.py", "import pickle\npickle.load(model)")
        archive.writestr("startup.pth", "import demo")
    config = tmp_path / "config"
    config.mkdir()
    (config / "risk_patterns.yaml").write_text(
        "regex_patterns: []\nkeywords: []\nsettings:\n  entropy_threshold: 10"
    )
    (config / "approved_packages.yaml").write_text("blocklist: [forbidden]")
    result = CliRunner().invoke(
        app, ["scan", str(wheel), "-f", "json", "-c", str(config), "--fail-on", "HIGH"]
    )
    assert result.exit_code == 10, result.output
    report = json.loads(result.stdout)
    assert report["requirements"] == ["forbidden>=2"]
    assert {"SHLK-DEPENDENCY", "SHLK-PICKLE", "SHLK-PTH"} <= {f["rule_id"] for f in report["findings"]}
