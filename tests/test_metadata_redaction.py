from sherlockscan.engine import scan_package
from sherlockscan.reporting import render


def test_dependency_url_credentials_are_redacted(tmp_path):
    (tmp_path / "pyproject.toml").write_text("""[project]
name="demo"
version="1"
dependencies=["dep @ https://user:private_password@example.test/file.whl?token=private_token"]
""")
    (tmp_path / "main.py").write_text("pass")
    report = scan_package(str(tmp_path))
    output = render(report)
    assert "private_password" not in output
    assert "private_token" not in output
    assert "[REDACTED]" in output
