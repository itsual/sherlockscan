"""Compatibility helpers. New callers should use engine.scan_package or ingestor.ingest."""

from pathlib import Path
import os
import shutil
import tempfile
from .exceptions import PackageNotFoundError, SherlockScanError
from .ingestor import ingest, read_archive, read_directory, safe_name

TEST_PATH_PARTS = {"test", "tests", "testing", "integration", "__pycache__", ".tox", ".nox", "build", "dist"}


def find_python_files(package_dir, include_tests=False):
    package_dir = Path(package_dir)
    if not package_dir.is_dir():
        return []
    found = []
    for current, dirs, files in os.walk(package_dir, followlinks=False):
        dirs[:] = [
            d
            for d in dirs
            if not (Path(current) / d).is_symlink() and (include_tests or d.lower() not in TEST_PATH_PARTS)
        ]
        found += [
            Path(current) / name
            for name in sorted(files)
            if name.endswith(".py") and not (Path(current) / name).is_symlink()
        ]
    return sorted(found)


def read_file_content(file_path):
    try:
        return Path(file_path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def get_code_snippet(file_path, line_number, context_lines=2):
    content = read_file_content(file_path)
    if content is None or not 1 <= line_number <= len(content.splitlines()):
        return "N/A"
    lines = content.splitlines()
    lines[line_number - 1] = "> " + lines[line_number - 1]
    return "\n".join(lines[max(0, line_number - context_lines - 1) : line_number + context_lines])


def _materialize(pkg, root):
    root = root.resolve()
    for name, data in pkg.files.items():
        destination = root / safe_name(name)
        # Never follow pre-existing filesystem links in this legacy extraction API.
        if not destination.resolve().is_relative_to(root) or any(
            p.is_symlink() for p in [destination, *destination.parents]
        ):
            raise ValueError("Extraction destination contains a link")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)


def _extract_archive(archive_path, extract_dir):
    try:
        pkg = read_archive(Path(archive_path))
        Path(extract_dir).mkdir(parents=True, exist_ok=True)
        _materialize(pkg, Path(extract_dir))
        return True
    except Exception:
        return False


def _find_package_root_and_metadata(extracted_path):
    pkg = read_directory(Path(extracted_path))
    return Path(extracted_path), pkg.name, pkg.version


def resolve_package_target(target):
    """Legacy path API; caller must remove the returned sherlock_extract_* directory.

    Unlike the v0.2 implementation, remote retrieval never runs pip or build hooks.
    """
    if Path(target).is_dir():
        return _find_package_root_and_metadata(Path(target))
    temporary = None
    try:
        pkg = ingest(target)
        temporary = Path(tempfile.mkdtemp(prefix="sherlock_extract_"))
        _materialize(pkg, temporary)
        return temporary, pkg.name, pkg.version
    except Exception as exc:
        if temporary:
            shutil.rmtree(temporary)
        raise SherlockScanError("Could not resolve package target statically") from exc
