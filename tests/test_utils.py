#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# tests/test_utils.py

import unittest
import tempfile
import os
import logging
import shutil
import zipfile
import tarfile
import subprocess # For mocking CalledProcessError
from pathlib import Path
from unittest.mock import patch, MagicMock

# Assume sherlockscan is installed or PYTHONPATH is set correctly
try:
    from sherlockscan import utils
    from sherlockscan.exceptions import PackageNotFoundError, SherlockScanError
    # Attempt to import metadata for mocking PathDistribution if needed
    try:
        from importlib import metadata as importlib_metadata
        METADATA_AVAILABLE = True
    except ImportError:
        try:
            import importlib_metadata # type: ignore
            METADATA_AVAILABLE = True
        except ImportError:
            METADATA_AVAILABLE = False
            # Define dummy if needed for type hints
            class DummyDist: pass
            importlib_metadata = MagicMock()
            importlib_metadata.PathDistribution = DummyDist # type: ignore
            
except ImportError as e:
     print(f"Warning: Could not import SherlockScan modules for utils tests: {e}")
     print("Utils tests will likely fail or be skipped.")
     # Define dummy classes/functions if needed for file parsing
     class SherlockScanError(Exception): pass
     class PackageNotFoundError(SherlockScanError): pass
     class utils: # type: ignore
         find_python_files = MagicMock(return_value=[])
         read_file_content = MagicMock(return_value=None)
         get_code_snippet = MagicMock(return_value="N/A")
         resolve_package_target = MagicMock(side_effect=SherlockScanError("Utils not loaded"))


# Disable logging during tests unless debugging
logging.disable(logging.CRITICAL)


class TestUtils(unittest.TestCase):
    """Unit tests for the utils module."""

    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = Path(tempfile.mkdtemp(prefix="sherlock_test_utils_"))

    def tearDown(self):
        """Remove the temporary directory."""
        shutil.rmtree(self.test_dir)

    def _create_nested_files(self):
        """Helper to create a nested structure with various files."""
        (self.test_dir / "file1.py").touch()
        (self.test_dir / "file2.txt").touch()
        subdir1 = self.test_dir / "subdir1"
        subdir1.mkdir()
        (subdir1 / "file3.py").touch()
        (subdir1 / "file4.pyc").touch() # Should be ignored
        subdir2 = self.test_dir / "subdir2"
        subdir2.mkdir()
        (subdir2 / "file5.py").touch()
        return [
            self.test_dir / "file1.py",
            subdir1 / "file3.py",
            subdir2 / "file5.py"
        ]

    # --- Test find_python_files ---
    def test_find_python_files_finds_all(self):
        """Test finding python files in nested directories."""
        expected_files = self._create_nested_files()
        found_files = utils.find_python_files(self.test_dir)
        # Convert to relative paths for comparison if needed, or use sets
        self.assertCountEqual(found_files, expected_files) # Checks elements regardless of order

    def test_find_python_files_empty_dir(self):
        """Test finding python files in an empty directory."""
        found_files = utils.find_python_files(self.test_dir)
        self.assertEqual(found_files, [])

    def test_find_python_files_not_a_dir(self):
        """Test finding python files when path is not a directory."""
        file_path = self.test_dir / "a_file.txt"
        file_path.touch()
        logging.disable(logging.WARNING) # Suppress expected warning
        found_files = utils.find_python_files(file_path)
        logging.disable(logging.CRITICAL) # Re-enable default
        self.assertEqual(found_files, [])

    # --- Test read_file_content ---
    def test_read_file_content_success(self):
        """Test reading content from an existing file."""
        file_path = self.test_dir / "read_test.txt"
        expected_content = "Line 1\nLine 2\nUTF-8: ñ✓"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(expected_content)
        
        content = utils.read_file_content(file_path)
        self.assertEqual(content, expected_content)

    def test_read_file_content_not_found(self):
        """Test reading content from a non-existent file."""
        logging.disable(logging.ERROR) # Suppress expected error
        content = utils.read_file_content(self.test_dir / "non_existent.txt")
        logging.disable(logging.CRITICAL)
        self.assertIsNone(content)

    # --- Test get_code_snippet ---
    def test_get_code_snippet_basic(self):
        """Test extracting a basic code snippet."""
        file_path = self.test_dir / "snippet_test.py"
        lines = [f"Line {i+1}" for i in range(10)]
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            
        snippet = utils.get_code_snippet(file_path, 5, context_lines=1)
        expected = "Line 4\n> Line 5\nLine 6"
        self.assertEqual(snippet, expected)

    def test_get_code_snippet_start_end(self):
        """Test extracting snippets at the start and end of the file."""
        file_path = self.test_dir / "snippet_test_edges.py"
        lines = [f"Line {i+1}" for i in range(5)]
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            
        snippet_start = utils.get_code_snippet(file_path, 1, context_lines=1)
        self.assertEqual(snippet_start, "> Line 1\nLine 2")
        
        snippet_end = utils.get_code_snippet(file_path, 5, context_lines=1)
        self.assertEqual(snippet_end, "Line 4\n> Line 5")

    def test_get_code_snippet_invalid_line(self):
        """Test extracting snippet with an invalid line number."""
        file_path = self.test_dir / "snippet_test_invalid.py"
        file_path.write_text("Line 1\nLine 2", encoding="utf-8")
        snippet = utils.get_code_snippet(file_path, 5, context_lines=1)
        self.assertEqual(snippet, "N/A")

    def test_get_code_snippet_file_not_found(self):
        """Test extracting snippet when the file doesn't exist."""
        snippet = utils.get_code_snippet(self.test_dir / "non_existent.py", 1, context_lines=1)
        self.assertEqual(snippet, "N/A")

    # --- Test resolve_package_target (Mocked Scenarios) ---
    # These tests are simplified and rely heavily on mocking internal helpers.

    @patch('sherlockscan.utils._find_package_root_and_metadata')
    def test_resolve_target_local_directory(self, mock_find_meta):
        """Test resolving a local directory target."""
        local_dir = self.test_dir / "my_local_package"
        local_dir.mkdir()
        (local_dir / "init.py").touch() # Dummy file
        
        # Mock the metadata finding part
        expected_name = "my-local-package"
        expected_version = "0.1.0"
        mock_find_meta.return_value = (local_dir, expected_name, expected_version)
        
        pkg_path, pkg_name, pkg_version = utils.resolve_package_target(str(local_dir))
        
        mock_find_meta.assert_called_once_with(local_dir)
        self.assertEqual(pkg_path, local_dir)
        self.assertEqual(pkg_name, expected_name)
        self.assertEqual(pkg_version, expected_version)

    @patch('sherlockscan.utils.subprocess.run')
    @patch('sherlockscan.utils._extract_archive')
    @patch('sherlockscan.utils._find_package_root_and_metadata')
    def test_resolve_target_pypi_download_success(self, mock_find_meta, mock_extract, mock_pip):
        """Test resolving a PyPI package with mocked successful download and extraction."""
        target_pkg = "requests"
        expected_name = "requests"
        expected_version = "2.25.1" # Example version
        
        # Configure mocks
        mock_pip.return_value = MagicMock(stdout="Successfully downloaded requests", stderr="", returncode=0)
        # Simulate pip downloading an archive file
        # Need to handle the fact that resolve_package_target creates a temp dir
        # We can patch tempfile.TemporaryDirectory or check calls to _run_pip_download
        
        mock_extract.return_value = True # Simulate successful extraction
        # Simulate metadata found after extraction
        # The path passed to mock_find_meta will be inside a temp dir
        mock_find_meta.return_value = (Path("/tmp/sherlock_download_xyz/extracted/requests-2.25.1"), expected_name, expected_version)

        # We need to ensure the check for downloaded files passes in _run_pip_download
        # Patch Path.iterdir within the scope of the test? Or patch the check itself?
        # Let's patch iterdir called on the temporary download directory.
        with patch('pathlib.Path.iterdir', return_value=[Path(f"{target_pkg}-1.0.tar.gz")]): # Simulate a downloaded file exists
             # Patch tempfile.TemporaryDirectory to control the path
             with patch('tempfile.TemporaryDirectory') as mock_tempdir:
                 # Make the mock return our test directory path when entered
                 mock_temp_path = self.test_dir / "temp_dl"
                 mock_temp_path.mkdir()
                 # Need to return an object with a 'name' attribute
                 mock_tempdir_instance = MagicMock()
                 mock_tempdir_instance.name = str(mock_temp_path)
                 mock_tempdir.return_value = mock_tempdir_instance

                 pkg_path, pkg_name, pkg_version = utils.resolve_package_target(target_pkg)

                 # Assertions
                 mock_pip.assert_called_once() # Check pip download was called
                 mock_extract.assert_called_once() # Check extraction was called
                 mock_find_meta.assert_called_once() # Check metadata parsing was called
                 self.assertEqual(pkg_name, expected_name)
                 self.assertEqual(pkg_version, expected_version)
                 # Path will be the mocked one from _find_package_root_and_metadata
                 self.assertEqual(pkg_path, Path("/tmp/sherlock_download_xyz/extracted/requests-2.25.1"))

    @patch('sherlockscan.utils.subprocess.run')
    def test_resolve_target_pypi_download_fail(self, mock_pip):
        """Test resolving a PyPI package when pip download fails."""
        target_pkg = "requests"
        # Configure mock pip to simulate failure
        mock_pip.side_effect = subprocess.CalledProcessError(
            cmd=['pip', 'download...'], returncode=1, stderr="Could not find package"
        )
        
        with self.assertRaises(PackageNotFoundError) as cm:
            utils.resolve_package_target(target_pkg)
            
        self.assertIn(f"Target package '{target_pkg}' could not be found", str(cm.exception))
        mock_pip.assert_called_once() # Check pip download was attempted


if __name__ == '__main__':
    unittest.main()

