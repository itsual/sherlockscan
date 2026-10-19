"""Build/install smoke checks run outside the source checkout (no PyPI upload)."""

from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import zipfile


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, timeout=180, **kwargs)


def main():
    root = Path(__file__).resolve().parents[1]
    artifacts = root / "dist"
    wheels = list(artifacts.glob("*.whl"))
    sources = list(artifacts.glob("*.tar.gz"))
    assert len(wheels) == len(sources) == 1, "Build into a clean dist directory"
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        assert "sherlockscan/config/risk_patterns.yaml" in names
        assert "sherlockscan/config/approved_packages.yaml" in names
        assert not any(n.startswith(("tests/", "integration/")) for n in names)
    with tempfile.TemporaryDirectory(prefix="sherlockscan-package-check-") as temporary:
        temporary = Path(temporary)
        for artifact in (wheels[0], sources[0]):
            target = temporary / ("wheel" if artifact.suffix == ".whl" else "sdist")
            run(
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--no-cache-dir",
                "--no-build-isolation",
                "--target",
                target,
                artifact,
                cwd=temporary,
            )
            # Isolated mode ignores PYTHONPATH and cwd. The test inserts only the
            # installed distribution, not this source checkout, ahead of runtime deps.
            code = """
import sys
sys.path.insert(0, sys.argv[1])
import sherlockscan
from importlib.resources import files
from pathlib import Path
from sherlockscan.engine import scan_package
from sherlockscan.reporting import render
assert sherlockscan.__version__ == '0.3.0'
assert str(Path(sherlockscan.__file__).resolve()).startswith(str(Path(sys.argv[1]).resolve()))
assert (files('sherlockscan.config') / 'risk_patterns.yaml').is_file()
project = Path('fixture')
project.mkdir(exist_ok=True)
(project/'pyproject.toml').write_text('[project]\\nname="smoke"\\nversion="1"\\ndependencies=[]')
(project/'main.py').write_text('answer = 42')
report = scan_package(str(project))
assert report['exit_code'] == 0, report['coverage']
assert report['findings'] == []
for format in ('json', 'md', 'sarif'):
    assert render(report, format)
print('installed-artifact-ok', sherlockscan.__version__)
"""
            run(sys.executable, "-I", "-c", code, target, cwd=temporary)
            candidates = [
                target / name
                for name in ("Scripts/sherlockscan.exe", "bin/sherlockscan.exe", "bin/sherlockscan")
            ]
            cli = next((path for path in candidates if path.exists()), candidates[0])
            env = dict(os.environ, PYTHONPATH=str(target))
            # pip --target creates scripts in Scripts on Windows and bin on POSIX.
            assert cli.exists(), cli
            run(cli, "version", cwd=temporary, env=env)


if __name__ == "__main__":
    main()
