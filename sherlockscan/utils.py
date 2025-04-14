#!/usr/bin/env python
# coding: utf-8

# In[ ]:


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

# Attempt to import metadata; handle Python < 3.8 or environment issues
try:
    from importlib import metadata as importlib_metadata
except ImportError:
    try:
        import importlib_metadata # type: ignore
    except ImportError:
        importlib_metadata = None # type: ignore

from .exceptions import PackageNotFoundError, SherlockScanError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def find_python_files(package_dir: Path) -> List[Path]:
    """
    Recursively finds all .py files within a given directory.

    Args:
        package_dir: The directory path to search within.

    Returns:
        A list of Path objects for found .py files.
    """
    logging.debug(f"Searching for Python files in: {package_dir}")
    if not package_dir.is_dir():
        logging.warning(f"Provided path is not a directory: {package_dir}")
        return []
    
    py_files = list(package_dir.rglob("*.py"))
    logging.info(f"Found {len(py_files)} Python files in {package_dir}.")
    return py_files


def read_file_content(file_path: Path) -> Optional[str]:
    """
    Safely reads the content of a file.

    Args:
        file_path: Path to the file.

    Returns:
        The file content as a string, or None if reading fails.
    """
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
    """
    Extracts a code snippet centered around a specific line number.

    Args:
        file_path: Path to the file.
        line_number: The target line number (1-based).
        context_lines: Number of lines to include before and after the target line.

    Returns:
        A string containing the code snippet, or "N/A" if extraction fails.
    """
    content = read_file_content(file_path)
    if content is None:
        return "N/A"
        
    lines = content.splitlines()
    if not (1 <= line_number <= len(lines)):
        return "N/A" # Invalid line number

    start = max(0, line_number - 1 - context_lines)
    end = min(len(lines), line_number + context_lines)
    
    snippet_lines = lines[start:end]
    
    # Indicate the target line if possible
    target_index_in_snippet = line_number - 1 - start
    if 0 <= target_index_in_snippet < len(snippet_lines):
         snippet_lines[target_index_in_snippet] = f"> {snippet_lines[target_index_in_snippet]}" # Mark target line

    return "\n".join(snippet_lines)


def _extract_archive(archive_path: Path, extract_dir: Path) -> bool:
    """Extracts zip or tar.gz archives."""
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
    """Uses pip download to fetch a package source."""
    # Using --no-deps as we analyze dependencies separately from installed metadata
    # Using --prefer-binary might speed things up but source analysis needs source dists ideally.
    # Let's try getting source first, fallback might be needed.
    # --no-binary :all: might be better for source analysis focus? Let's try default first.
    command = [
        sys.executable, # Use the same python interpreter running the script
        "-m", "pip", "download",
        "--no-deps",
        "--dest", str(download_dir),
        package_name
    ]
    logging.info(f"Attempting to download package '{package_name}' using pip: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=300) # 5 min timeout
        logging.debug(f"pip download stdout:\n{result.stdout}")
        logging.debug(f"pip download stderr:\n{result.stderr}")
        # Check if download dir actually contains something for the package
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
    """
    Attempts to find the package root and parse basic metadata (name, version)
    from an extracted archive directory. This is a simplified approach.
    """
    package_name = None
    package_version = None
    package_root = extracted_path

    # Strategy 1: Look for .dist-info or .egg-info directories (common in wheels/installs)
    metadata_dirs = list(extracted_path.glob('*.dist-info')) + list(extracted_path.glob('*.egg-info'))
    if metadata_dirs and importlib_metadata:
        try:
            # Use importlib.metadata on the path if possible (requires specific layout)
            dist = importlib_metadata.PathDistribution(metadata_dirs[0])
            package_name = dist.metadata['Name']
            package_version = dist.version
            logging.info(f"Found metadata via PathDistribution: Name={package_name}, Version={package_version}")
            # Assume extracted path is the root if dist-info found at top level
            return package_root, package_name, package_version
        except Exception as e:
            logging.warning(f"Could not parse metadata using PathDistribution from {metadata_dirs[0]}: {e}. Falling back.")
            # Fallback: Try reading METADATA file directly
            metadata_file = metadata_dirs[0] / 'METADATA'
            if not metadata_file.exists() and metadata_dirs[0].name.endswith('.egg-info'):
                 metadata_file = metadata_dirs[0] / 'PKG-INFO' # Fallback for egg-info

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

    # Strategy 2: Look for setup.py or pyproject.toml (common in source distributions)
    # Often the archive extracts into a subdirectory like package-name-version/
    potential_root = extracted_path
    setup_py = list(extracted_path.rglob('setup.py'))
    pyproject_toml = list(extracted_path.rglob('pyproject.toml'))

    if setup_py:
        potential_root = setup_py[0].parent
        logging.debug(f"Found setup.py, potential root: {potential_root}")
        # Parsing setup.py reliably for metadata without execution is very hard.
        # We might just use the directory name as a hint or skip metadata extraction here.
    elif pyproject_toml:
        potential_root = pyproject_toml[0].parent
        logging.debug(f"Found pyproject.toml, potential root: {potential_root}")
        # Try parsing pyproject.toml for name/version
        try:
            import toml # Import here to avoid making it a hard dependency if only setup.py is used
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


    # If name/version still unknown, try to infer from the top-level directory name
    # (common pattern: package-name-version.tar.gz extracts to package-name-version/)
    if not package_name and potential_root != extracted_path:
         dir_name = potential_root.name
         # Very basic parsing: assumes name-version format
         parts = dir_name.split('-')
         if len(parts) > 1 and parts[-1][0].isdigit(): # Check if last part looks like a version
             package_version = parts[-1]
             package_name = '-'.join(parts[:-1])
             logging.info(f"Inferred metadata from directory: Name={package_name}, Version={package_version}")


    if not package_name:
         logging.warning(f"Could not determine package name for path: {extracted_path}")
         # Use directory name as fallback package name?
         package_name = extracted_path.name

    logging.info(f"Determined package root: {potential_root}")
    return potential_root, package_name, package_version


# --- Main Utility Function ---

def resolve_package_target(target: str) -> Tuple[Path, str, Optional[str]]:
    """
    Resolves a package target (name or path) to a local directory path
    containing the package source, alongside its name and version.

    Handles local directories, archives (wheel, sdist), and downloading from PyPI.
    Manages temporary directories for downloads/extractions.

    Args:
        target: Package name (e.g., "requests") or path to directory/archive.

    Returns:
        A tuple: (package_source_directory, package_name, package_version).
        The source directory might be temporary and should be cleaned up by the caller if needed.

    Raises:
        PackageNotFoundError: If the target cannot be resolved.
        SherlockScanError: For other errors during processing.
    """
    target_path = Path(target)
    temp_dir_manager = None # To hold temp directory object if created

    try:
        if target_path.is_dir():
            logging.info(f"Target is a local directory: {target_path}")
            # Assume it's the package root or contains it directly
            # We might need to refine root finding if it's not the immediate dir
            package_root, name, version = _find_package_root_and_metadata(target_path)
            if not name: name = target_path.name # Fallback name
            return package_root, name, version

        elif target_path.is_file():
            logging.info(f"Target is a local file: {target_path}")
            # Assume it's an archive, try extracting
            temp_dir_manager = tempfile.TemporaryDirectory(prefix="sherlock_extract_")
            extract_dir = Path(temp_dir_manager.name)
            if _extract_archive(target_path, extract_dir):
                 # Find metadata within the extracted content
                 package_root, name, version = _find_package_root_and_metadata(extract_dir)
                 if not name: name = target_path.stem.split('-')[0] # Infer name from filename
                 # Important: The caller needs to handle cleanup of the temp dir eventually.
                 # For now, we return the path within the temp dir.
                 # A better approach might involve context managers.
                 logging.warning("Returning path within temporary directory. Ensure cleanup.")
                 # We detach the temp dir manager here so it doesn't get cleaned up immediately
                 # Caller MUST handle cleanup later. This is not ideal.
                 # TODO: Refactor using context manager or pass temp_dir_manager back.
                 _temp_dir_to_clean = temp_dir_manager # Store ref
                 temp_dir_manager = None # Prevent __exit__
                 return package_root, name, version
            else:
                 raise SherlockScanError(f"Failed to extract archive: {target_path}")

        else:
            # Assume target is a package name from PyPI
            logging.info(f"Target '{target}' not found locally, attempting PyPI download.")
            temp_dir_manager = tempfile.TemporaryDirectory(prefix="sherlock_download_")
            download_dir = Path(temp_dir_manager.name)
            if _run_pip_download(target, download_dir):
                # Find the downloaded archive (wheel or sdist)
                downloaded_files = list(download_dir.iterdir())
                if not downloaded_files:
                    raise SherlockScanError(f"Pip download succeeded but no files found in {download_dir}")

                # Prefer source dist (.tar.gz) if available, otherwise wheel (.whl)
                archive_path = None
                sdist_files = [f for f in downloaded_files if f.name.endswith('.tar.gz') or f.name.endswith('.zip')] # zip for some sdists
                wheel_files = [f for f in downloaded_files if f.name.endswith('.whl')]

                if sdist_files:
                    archive_path = sdist_files[0]
                    logging.info(f"Found downloaded source distribution: {archive_path}")
                elif wheel_files:
                    archive_path = wheel_files[0]
                    logging.info(f"Found downloaded wheel file: {archive_path}")
                else:
                    raise SherlockScanError(f"Downloaded files, but could not find source dist or wheel for {target} in {download_dir}")

                # Extract the archive
                extract_dir = download_dir / "extracted" # Extract within download dir
                extract_dir.mkdir()
                if _extract_archive(archive_path, extract_dir):
                    package_root, name, version = _find_package_root_and_metadata(extract_dir)
                    if not name: name = target # Use original target name if parsing fails
                    logging.warning("Returning path within temporary directory. Ensure cleanup.")
                    _temp_dir_to_clean = temp_dir_manager # Store ref
                    temp_dir_manager = None # Prevent __exit__
                    return package_root, name, version
                else:
                    raise SherlockScanError(f"Failed to extract downloaded archive: {archive_path}")
            else:
                raise PackageNotFoundError(target)

    except Exception as e:
        # Clean up temp dir if created and an error occurred
        if temp_dir_manager:
            temp_dir_manager.cleanup()
        # Re-raise specific errors or wrap in SherlockScanError
        if isinstance(e, (PackageNotFoundError, SherlockScanError)):
            raise e
        else:
            raise SherlockScanError(f"Failed to resolve package target '{target}': {e}") from e
    finally:
         # Ensure temp dir manager is cleaned up if not detached
         if temp_dir_manager:
             temp_dir_manager.cleanup()


# Example Usage (for testing purposes)
if __name__ == '__main__':
    
    # --- Test find_python_files ---
    print("--- Testing find_python_files ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        (tmppath / "file1.py").touch()
        (tmppath / "subdir").mkdir()
        (tmppath / "subdir/file2.py").touch()
        (tmppath / "subdir/file3.txt").touch()
        (tmppath / "another.py").touch()
        
        py_files = find_python_files(tmppath)
        print(f"Found files: {[f.relative_to(tmppath) for f in py_files]}")
        assert len(py_files) == 3

    # --- Test read_file_content ---
    print("\n--- Testing read_file_content ---")
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmpfile:
        tmpfile.write("Line 1\nLine 2\nLine 3")
        tmpfilepath = Path(tmpfile.name)
    
    content = read_file_content(tmpfilepath)
    print(f"Read content:\n{content}")
    assert content == "Line 1\nLine 2\nLine 3"
    os.remove(tmpfilepath)
    
    content_missing = read_file_content(Path("non_existent_file.txt"))
    assert content_missing is None

    # --- Test get_code_snippet ---
    print("\n--- Testing get_code_snippet ---")
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as tmpfile:
         lines = [f"Line {i+1}" for i in range(10)]
         tmpfile.write("\n".join(lines))
         tmpfilepath = Path(tmpfile.name)

    snippet_middle = get_code_snippet(tmpfilepath, 5, context_lines=1)
    print(f"Snippet around line 5:\n{snippet_middle}")
    assert snippet_middle == "Line 4\n> Line 5\nLine 6"

    snippet_start = get_code_snippet(tmpfilepath, 1, context_lines=1)
    print(f"Snippet around line 1:\n{snippet_start}")
    assert snippet_start == "> Line 1\nLine 2"

    snippet_end = get_code_snippet(tmpfilepath, 10, context_lines=1)
    print(f"Snippet around line 10:\n{snippet_end}")
    assert snippet_end == "Line 9\n> Line 10"

    snippet_invalid = get_code_snippet(tmpfilepath, 11, context_lines=1)
    print(f"Snippet for invalid line 11: {snippet_invalid}")
    assert snippet_invalid == "N/A"
    os.remove(tmpfilepath)

    # --- Test resolve_package_target (Basic - requires pip) ---
    # Note: This test requires 'pip' and network access. It might fail in restricted environments.
    # It also leaves a temporary directory behind due to the cleanup issue mentioned in the code.
    print("\n--- Testing resolve_package_target (requires pip, network) ---")
    target_pkg = "typer" # Use a relatively small, common package
    try:
        print(f"Attempting to resolve target: {target_pkg}")
        # This creates a temp dir that currently isn't cleaned up by this test code
        pkg_path, pkg_name, pkg_version = resolve_package_target(target_pkg)
        print(f"Resolved: Path={pkg_path}, Name={pkg_name}, Version={pkg_version}")
        # Basic assertions
        assert pkg_name.lower() == target_pkg.lower()
        assert pkg_path.exists()
        # TODO: Add manual cleanup step here for the returned pkg_path if it's temporary
        if "sherlock_download_" in str(pkg_path) or "sherlock_extract_" in str(pkg_path):
             print(f"NOTE: Test created temporary directory: {pkg_path}. Manual cleanup might be needed if it persists.")
             # shutil.rmtree(pkg_path.parent) # Example cleanup (be careful!)
    except (PackageNotFoundError, SherlockScanError, Exception) as e:
        print(f"Could not resolve '{target_pkg}': {e}")
        print("This might be due to network issues, pip configuration, or timeout.")


