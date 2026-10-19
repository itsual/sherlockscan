"""Read untrusted distribution bytes without importing, installing or building them."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse
from urllib.request import urlopen

import toml
from packaging.requirements import Requirement
from packaging.tags import sys_tags
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version


@dataclass(frozen=True)
class Limits:
    download: int = 100 * 1024 * 1024
    total: int = 250 * 1024 * 1024
    member: int = 25 * 1024 * 1024
    count: int = 5000
    ratio: int = 1000
    seconds: int = 60


@dataclass
class Package:
    name: str = "unknown"
    version: str | None = None
    requirements: list[str] = field(default_factory=list)
    files: dict[str, bytes] = field(default_factory=dict)
    coverage: list[str] = field(default_factory=list)
    metadata_source: str | None = None
    artifact: dict = field(default_factory=dict)
    dependency_groups: dict[str, list[str]] = field(default_factory=dict)


def safe_name(name: str) -> str:
    # Validate both Windows and POSIX syntax regardless of scanner host.
    parts = name.split("/")
    if (
        not name
        or "\\" in name
        or ":" in name
        or "\x00" in name
        or name.startswith("/")
        or any(p in {"..", "."} for p in parts)
        or any(p.endswith((" ", ".")) for p in parts if p)
    ):
        raise ValueError("Unsafe archive member path")
    return str(PurePosixPath(name))


def _bounded_read(stream, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Input exceeds byte limit")
    return data


def _metadata(pkg: Package, prefer_project: bool = False) -> None:
    # Root wheel metadata takes precedence; nested dependency metadata is ambiguous.
    wheel = [n for n in pkg.files if len(PurePosixPath(n).parts) == 2 and n.endswith(".dist-info/METADATA")]
    roots = [n for n in pkg.files if PurePosixPath(n).name == "PKG-INFO"]
    candidates = wheel or sorted(roots, key=lambda n: (len(PurePosixPath(n).parts), n))
    if len(wheel) > 1:
        raise ValueError("Ambiguous wheel metadata")
    if prefer_project and "pyproject.toml" in pkg.files:
        candidates = []
    if candidates:
        source = candidates[0]
        msg = BytesParser().parsebytes(pkg.files[source], headersonly=True)
        if not msg.get("Name") or not msg.get("Version"):
            raise ValueError("Distribution metadata requires Name and Version")
        pkg.name, pkg.version = msg["Name"], msg["Version"]
        pkg.requirements = list(msg.get_all("Requires-Dist", []))
        pkg.metadata_source = source
        dynamic_fields = {value.lower() for value in msg.get_all("Dynamic", [])}
        if dynamic_fields & {"requires-dist", "name", "version", "requires-python"}:
            pkg.coverage.append("Source metadata declares dynamic fields; dependencies may be incomplete.")
        if (
            roots
            and not wheel
            and not msg.get("Metadata-Version", "").startswith(("2.2", "2.3", "2.4", "2.5"))
        ):
            pkg.coverage.append("Older source metadata may omit dynamic dependencies.")
    else:
        projects = sorted(
            (n for n in pkg.files if PurePosixPath(n).name == "pyproject.toml"),
            key=lambda n: (len(PurePosixPath(n).parts), n),
        )
        if projects:
            source = projects[0]
            data = toml.loads(pkg.files[source].decode("utf-8"))
            project = data.get("project", {})
            pkg.name = project.get("name", pkg.name)
            pkg.version = project.get("version")
            pkg.requirements = project.get("dependencies", [])
            pkg.dependency_groups = project.get("optional-dependencies", {})
            if not isinstance(pkg.requirements, list) or not all(
                isinstance(x, str) for x in pkg.requirements
            ):
                raise ValueError("project.dependencies must be a list of requirements")
            if not isinstance(pkg.dependency_groups, dict) or any(
                not isinstance(v, list) or not all(isinstance(x, str) for x in v)
                for v in pkg.dependency_groups.values()
            ):
                raise ValueError("Invalid optional-dependencies")
            pkg.metadata_source = source
            if project.get("dynamic") or not project:
                pkg.coverage.append("Dynamic or non-PEP-621 metadata cannot be resolved statically.")
        else:
            pkg.coverage.append("No static package metadata found; dependencies are unknown.")
    if pkg.name == "unknown" or pkg.version is None:
        pkg.coverage.append("Package identity or version is unknown.")
    # Preserve the original requirement, including markers/extras/constraints.
    for req in pkg.requirements + [r for group in pkg.dependency_groups.values() for r in group]:
        Requirement(req)


def read_archive(path: Path, limits: Limits = Limits()) -> Package:
    pkg = Package(artifact={"filename": path.name})
    if path.stat().st_size > limits.download:
        raise ValueError("Compressed artifact exceeds download limit")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    pkg.artifact["sha256"] = digest.hexdigest()
    total = 0
    seen = set()
    start = time.monotonic()

    def add(name, size, stream):
        nonlocal total
        name = safe_name(name)
        key = name.casefold()
        if key in seen:
            raise ValueError("Duplicate or case-colliding archive member")
        seen.add(key)
        total += size
        if len(seen) > limits.count or size > limits.member or total > limits.total:
            raise ValueError("Archive exceeds member/count/total limits")
        if time.monotonic() - start > limits.seconds:
            raise ValueError("Archive processing time budget exceeded")
        if stream is not None:
            data = _bounded_read(stream, min(size, limits.member))
            if len(data) != size:
                raise ValueError("Archive member size mismatch")
            pkg.files[name] = data

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > limits.count:
                raise ValueError("Archive exceeds member count")
            for entry in archive.infolist():
                mode = entry.external_attr >> 16
                if stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR} or entry.flag_bits & 1:
                    raise ValueError("Archive link, device or encrypted member rejected")
                if entry.file_size / max(entry.compress_size, 1) > limits.ratio:
                    raise ValueError("Archive compression ratio exceeds limit")
                if entry.is_dir():
                    add(entry.filename, 0, None)
                else:
                    with archive.open(entry) as stream:
                        add(entry.filename, entry.file_size, stream)
    else:
        # Stream TAR entries: never allocate an unlimited member list or extract.
        with tarfile.open(path, "r|*") as archive:
            for entry in archive:
                if not (entry.isfile() or entry.isdir()):
                    raise ValueError("Archive links/devices/special members rejected")
                stream = archive.extractfile(entry) if entry.isfile() else None
                try:
                    add(entry.name, entry.size, stream)
                finally:
                    if stream:
                        stream.close()
    _metadata(pkg)
    return pkg


def read_directory(root: Path, limits: Limits = Limits()) -> Package:
    root = root.resolve()
    pkg = Package(artifact={"kind": "directory", "filename": root.name})
    total = count = 0
    start = time.monotonic()
    skipped = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".nox",
        "build",
        "dist",
        ".pytest_cache",
        ".localtmp",
        ".package-check",
        ".release-check",
        "review-artifacts",
    }
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in skipped)
        for d in list(dirs):
            if (Path(current) / d).is_symlink():
                dirs.remove(d)
                pkg.coverage.append("Symbolic-link directories were not followed.")
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                pkg.coverage.append("Symbolic-link or special files were skipped.")
                continue
            size = path.stat().st_size
            total += size
            count += 1
            if (
                count > limits.count
                or total > limits.total
                or size > limits.member
                or time.monotonic() - start > limits.seconds
            ):
                raise ValueError("Directory exceeds scan limits")
            with path.open("rb") as stream:
                pkg.files[path.relative_to(root).as_posix()] = _bounded_read(stream, limits.member)
    _metadata(pkg, prefer_project=True)
    return pkg


def _https(url: str, allowed: set[str]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed or parsed.username or parsed.password:
        raise ValueError("Unexpected registry URL")


def fetch_pypi(spec: str, destination: Path, limits: Limits = Limits()) -> dict:
    match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:==([A-Za-z0-9.!+_-]+))?", spec)
    if not match:
        raise ValueError("Use a PyPI name or name==version; URLs and arbitrary pip arguments are unsupported")
    name, version = match.groups()
    endpoint = f"https://pypi.org/pypi/{canonicalize_name(name)}"
    endpoint += f"/{version}/json" if version else "/json"
    with urlopen(endpoint, timeout=15) as response:
        _https(response.geturl(), {"pypi.org"})
        payload = json.loads(_bounded_read(response, 5 * 1024 * 1024))
    compatible = set(sys_tags())
    if version and Version(payload["info"]["version"]) != Version(version):
        raise ValueError("Registry version differs from requested version")
    artifacts = []
    for item in payload["urls"]:
        if item.get("yanked") or item["packagetype"] not in {"bdist_wheel", "sdist"}:
            continue
        if item.get("requires_python"):
            import sys

            if not SpecifierSet(item["requires_python"]).contains(".".join(map(str, sys.version_info[:3]))):
                continue
        if item["filename"].endswith(".whl"):
            _, _, _, tags = parse_wheel_filename(item["filename"])
            if not tags & compatible:
                continue
        artifacts.append(item)
    if not artifacts:
        raise ValueError("No non-yanked compatible artifact available")
    artifacts.sort(key=lambda x: (x["packagetype"] != "bdist_wheel", x["filename"]))
    item = artifacts[0]
    _https(item["url"], {"files.pythonhosted.org"})
    if item.get("size", 0) > limits.download:
        raise ValueError("Artifact exceeds download limit")
    start = time.monotonic()
    digest = hashlib.sha256()
    count = 0
    with urlopen(item["url"], timeout=15) as response, destination.open("wb") as target:
        _https(response.geturl(), {"files.pythonhosted.org"})
        while chunk := response.read(65536):
            count += len(chunk)
            if count > limits.download or time.monotonic() - start > limits.seconds:
                raise ValueError("Download resource budget exceeded")
            digest.update(chunk)
            target.write(chunk)
    if digest.hexdigest() != item["digests"]["sha256"]:
        raise ValueError("Artifact SHA-256 verification failed")
    return {
        "filename": item["filename"],
        "sha256": digest.hexdigest(),
        "source": "pypi",
        "expected_name": canonicalize_name(name),
        "expected_version": payload["info"]["version"],
    }


def ingest(target: str, limits: Limits = Limits()) -> Package:
    import tempfile

    path = Path(target)
    if path.is_dir():
        return read_directory(path, limits)
    if path.is_file():
        return read_archive(path, limits)
    with tempfile.TemporaryDirectory(prefix="sherlockscan-") as temporary:
        path = Path(temporary) / "artifact"
        artifact = fetch_pypi(target, path, limits)
        pkg = read_archive(path, limits)
        if canonicalize_name(pkg.name) != artifact["expected_name"] or Version(pkg.version or "0") != Version(
            artifact["expected_version"]
        ):
            raise ValueError("Artifact identity does not match registry metadata")
        pkg.artifact = artifact
        return pkg
