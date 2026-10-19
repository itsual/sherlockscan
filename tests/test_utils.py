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

    # --- Safe archive extraction ---
    def test_extract_archive_rejects_zip_path_traversal(self):
        archive_path = self.test_dir / "unsafe.zip"
        extract_dir = self.test_dir / "extract"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("../escaped.py", "print('unsafe')")
        self.assertFalse(utils._extract_archive(archive_path, extract_dir))
        self.assertFalse((self.test_dir / "escaped.py").exists())

    def test_extract_archive_extracts_safe_zip(self):
        archive_path = self.test_dir / "safe.zip"
        extract_dir = self.test_dir / "extract"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("package/module.py", "VALUE = 1\n")
        self.assertTrue(utils._extract_archive(archive_path, extract_dir))
        self.assertEqual((extract_dir / "package" / "module.py").read_text(), "VALUE = 1\n")

    def test_find_python_files_excludes_tests_by_default(self):
        (self.test_dir / "main.py").touch()
        tests_dir = self.test_dir / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_main.py").touch()
        self.assertEqual(utils.find_python_files(self.test_dir), [self.test_dir / "main.py"])
        self.assertCountEqual(
            utils.find_python_files(self.test_dir, include_tests=True),
            [self.test_dir / "main.py", tests_dir / "test_main.py"],
        )

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

    def test_remote_resolution_uses_static_ingestor(self):
        from sherlockscan.ingestor import Package
        package = Package(name="demo", version="1.0", files={"demo.py": b"value=1"})
        with patch('sherlockscan.utils.ingest', return_value=package) as ingest:
            path, name, version = utils.resolve_package_target("demo==1.0")
        try:
            ingest.assert_called_once_with("demo==1.0")
            self.assertEqual((name, version), ("demo", "1.0"))
            self.assertEqual((path / "demo.py").read_bytes(), b"value=1")
        finally:
            shutil.rmtree(path)

    def test_remote_resolution_failure_is_not_clean(self):
        with patch('sherlockscan.utils.ingest', side_effect=ValueError("bad artifact")):
            with self.assertRaises(SherlockScanError):
                utils.resolve_package_target("demo")

if __name__ == '__main__':
    unittest.main()
