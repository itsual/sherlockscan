#!/usr/bin/env python
# coding: utf-8

# sherlockscan/utils.py

import logging
import os
import sys
import shutil
import subprocess
import tarfile
import zipfile
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

try:
    from importlib import metadata as importlib_metadata
except ImportError:
    try:
        import importlib_metadata # type: ignore
    except ImportError:
        importlib_metadata = None # type: ignore

from .exceptions import PackageNotFoundError, SherlockScanError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def find_python_files(package_dir: Path) -> List[Path]:
    logging.debug(f"Searching for Python files in: {package_dir}")
    if not package_dir.is_dir():
        logging.warning(f"Provided path is not a directory: {package_dir}")
        return []
    py_files = list(package_dir.rglob("*.py"))
    logging.info(f"Found {len(py_files)} Python files in {package_dir}.")
    return py_files


def read_file_content(file_path: Path) -> Optional[str]:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None


def get_code_snippet(file_path: Path, line_number: int, context_lines: int = 2) -> str:
    content = read_file_content(file_path)
    if content is None:
        return "N/A"
    lines = content.splitlines()
    if not (1 <= line_number <= len(lines)):
        return "N/A"
    start = max(0, line_number - 1 - context_lines)
    end = min(len(lines), line_number + context_lines)
    snippet_lines = lines[start:end]
    target_index_in_snippet = line_number - 1 - start
    if 0 <= target_index_in_snippet < len(snippet_lines):
         snippet_lines[target_index_in_snippet] = f"> {snippet_lines[target_index_in_snippet]}"
    return "\n".join(snippet_lines)


def _extract_archive(archive_path: Path, extract_dir: Path) -> bool:
    try:
        if zipfile.is_zipfile(archive_path):
            logging.info(f"Extracting zip archive: {archive_path} to {extract_dir}")
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            return True
        elif tarfile.is_tarfile(archive_path):
            logging.info(f"Extracting tar archive: {archive_path} to {extract_dir}")
            with tarfile.open(archive_path, "r:*") as tar_ref:
                tar_ref.extractall(extract_dir)
            return True
        else:
            logging.warning(f"Unsupported archive type: {archive_path}")
            return False
    except Exception as e:
        logging.error(f"Failed to extract archive {archive_path}: {e}")
        return False

def _run_pip_download(package_name: str, download_dir: Path) -> bool:
    command = [
        sys.executable,
        "-m", "pip", "download",
        "--no-deps",
        "--dest", str(download_dir),
        package_name
    ]
    logging.info(f"Attempting to download package '{package_name}' using pip: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=300)
        logging.debug(f"pip download stdout:\n{result.stdout}")
        logging.debug(f"pip download stderr:\n{result.stderr}")
        if any(p.name.lower().startswith(package_name.lower().replace('-', '_')) for p in download_dir.iterdir()):
             logging.info(f"Successfully downloaded package '{package_name}' artifacts.")
             return True
        else:
             logging.error(f"pip download completed but no artifacts found for '{package_name}' in {download_dir}.")
             logging.error(f"Pip Output (stderr):\n{result.stderr}")
             return False
    except FileNotFoundError:
        logging.error("Error: 'pip' command not found. Make sure pip is installed and in your PATH.")
        return False
    except subprocess.CalledProcessError as e:
        logging.error(f"pip download failed for '{package_name}'.")
        logging.error(f"Command: {' '.join(e.cmd)}")
        logging.error(f"Return Code: {e.returncode}")
        logging.error(f"Output (stdout):\n{e.stdout}")
        logging.error(f"Output (stderr):\n{e.stderr}")
        return False
    except subprocess.TimeoutExpired:
        logging.error(f"pip download timed out for '{package_name}'.")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during pip download for '{package_name}': {e}")
        return False


def _find_package_root_and_metadata(extracted_path: Path) -> Optional[Tuple[Path, Optional[str], Optional[str]]]:
    package_name = None
    package_version = None
    package_root = extracted_path

    metadata_dirs = list(extracted_path.glob('*.dist-info')) + list(extracted_path.glob('*.egg-info'))
    if metadata_dirs and importlib_metadata:
        try:
            dist = importlib_metadata.PathDistribution(metadata_dirs[0])
            package_name = dist.metadata['Name']
            package_version = dist.version
            logging.info(f"Found metadata via PathDistribution: Name={package_name}, Version={package_version}")
            return package_root, package_name, package_version
        except Exception as e:
            logging.warning(f"Could not parse metadata using PathDistribution from {metadata_dirs[0]}: {e}. Falling back.")
            metadata_file = metadata_dirs[0] / 'METADATA'
            if not metadata_file.exists() and metadata_dirs[0].name.endswith('.egg-info'):
                 metadata_file = metadata_dirs[0] / 'PKG-INFO'
            if metadata_file.exists():
                logging.debug(f"Attempting to parse metadata file: {metadata_file}")
                content = read_file_content(metadata_file)
                if content:
                    for line in content.splitlines():
                        if line.lower().startswith("name:"):
                            package_name = line.split(":", 1)[1].strip()
                        elif line.lower().startswith("version:"):
                            package_version = line.split(":", 1)[1].strip()
                        if package_name and package_version:
                            break
                    logging.info(f"Found metadata via file parsing: Name={package_name}, Version={package_version}")
                    return package_root, package_name, package_version

    potential_root = extracted_path
    setup_py = list(extracted_path.rglob('setup.py'))
    pyproject_toml = list(extracted_path.rglob('pyproject.toml'))

    if setup_py:
        potential_root = setup_py[0].parent
        logging.debug(f"Found setup.py, potential root: {potential_root}")
    elif pyproject_toml:
        potential_root = pyproject_toml[0].parent
        logging.debug(f"Found pyproject.toml, potential root: {potential_root}")
        try:
            import toml
            content = read_file_content(pyproject_toml[0])
            if content:
                 data = toml.loads(content)
                 package_name = data.get("project", {}).get("name") or data.get("tool", {}).get("poetry", {}).get("name")
                 package_version = data.get("project", {}).get("version") or data.get("tool", {}).get("poetry", {}).get("version")
                 if package_name:
                     logging.info(f"Found metadata via pyproject.toml: Name={package_name}, Version={package_version}")
        except ImportError:
             logging.warning("Cannot parse pyproject.toml metadata: 'toml' library not installed.")
        except Exception as e:
             logging.warning(f"Failed to parse pyproject.toml for metadata: {e}")

    if not package_name and potential_root != extracted_path:
         dir_name = potential_root.name
         parts = dir_name.split('-')
         if len(parts) > 1 and parts[-1][0].isdigit():
             package_version = parts[-1]
             package_name = '-'.join(parts[:-1])
             logging.info(f"Inferred metadata from directory: Name={package_name}, Version={package_version}")

    if not package_name:
         logging.warning(f"Could not determine package name for path: {extracted_path}")
         package_name = extracted_path.name

    logging.info(f"Determined package root: {potential_root}")
    return potential_root, package_name, package_version


def resolve_package_target(target: str) -> Tuple[Path, str, Optional[str]]:
    target_path = Path(target)
    temp_dir_path = None

    try:
        if target_path.is_dir():
            logging.info(f"Target is a local directory: {target_path}")
            package_root, name, version = _find_package_root_and_metadata(target_path)
            if not name: name = target_path.name
            return package_root, name, version

        elif target_path.is_file():
            logging.info(f"Target is a local file: {target_path}")
            temp_dir_path = tempfile.mkdtemp(prefix="sherlock_extract_")
            extract_dir = Path(temp_dir_path)
            if _extract_archive(target_path, extract_dir):
                 package_root, name, version = _find_package_root_and_metadata(extract_dir)
                 if not name: name = target_path.stem.split('-')[0]
                 logging.warning("Returning path within temporary directory. Ensure cleanup.")
                 return package_root, name, version
            else:
                 raise SherlockScanError(f"Failed to extract archive: {target_path}")

        else:
            logging.info(f"Target '{target}' not found locally, attempting PyPI download.")
            temp_dir_path = tempfile.mkdtemp(prefix="sherlock_download_")
            download_dir = Path(temp_dir_path)
            if _run_pip_download(target, download_dir):
                downloaded_files = list(download_dir.iterdir())
                if not downloaded_files:
                    raise SherlockScanError(f"Pip download succeeded but no files found in {download_dir}")

                archive_path = None
                sdist_files = [f for f in downloaded_files if f.name.endswith('.tar.gz') or f.name.endswith('.zip')]
                wheel_files = [f for f in downloaded_files if f.name.endswith('.whl')]

                if sdist_files:
                    archive_path = sdist_files[0]
                    logging.info(f"Found downloaded source distribution: {archive_path}")
                elif wheel_files:
                    archive_path = wheel_files[0]
                    logging.info(f"Found downloaded wheel file: {archive_path}")
                else:
                    raise SherlockScanError(f"Downloaded files, but could not find source dist or wheel for {target} in {download_dir}")

                extract_dir = download_dir / "extracted"
                extract_dir.mkdir()
                if _extract_archive(archive_path, extract_dir):
                    package_root, name, version = _find_package_root_and_metadata(extract_dir)
                    if not name: name = target
                    logging.warning("Returning path within temporary directory. Ensure cleanup.")
                    return package_root, name, version
                else:
                    raise SherlockScanError(f"Failed to extract downloaded archive: {archive_path}")
            else:
                raise PackageNotFoundError(target)

    except Exception as e:
        if temp_dir_path:
            shutil.rmtree(temp_dir_path, ignore_errors=True)
        if isinstance(e, (PackageNotFoundError, SherlockScanError)):
            raise e
        else:
            raise SherlockScanError(f"Failed to resolve package target '{target}': {e}") from e
