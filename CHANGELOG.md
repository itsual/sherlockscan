# Changelog

All notable changes to SherlockScan are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Removed orphaned `[project.urls]` table from `pyproject.toml` that caused build failures
- Added missing `import re` in `deps.py`
- Fixed `None.strip()` crash in Markdown report formatter
- Replaced placeholder CLI helper stubs with real delegates to `utils.py`
- Fixed README rendering: closed unclosed Mermaid code fence, quoted special characters in node labels, restored full Markdown structure
- Removed broken `yourusername` placeholder badges and URLs
- Fixed invalid JSON example in README (removed JavaScript-style comments)

### Changed
- Replaced deprecated `datetime.datetime.utcnow()` with `datetime.datetime.now(timezone.utc)` in JSON formatter
- Converted invalid escape sequences in `heuristics.py` and `test_end_to_end.py` to raw strings

### Removed
- Unused `importlib_metadata` import block in `cli.py`

### Tests
- Fixed missing `typing` imports across test files
- Corrected CLI invocation in test mocks
- Fixed line-number assertions for triple-quoted test strings
- Fixed YAML quoting in test configuration fixtures
- All 75 unit and integration tests pass

## [0.1.0] - 2025-04-13

### Added
- Initial MVP release
- AST-based static analysis for risky calls (`eval`, `exec`, `pickle.load`, `os.system`, `subprocess`) and suspicious imports
- Heuristic scanning with configurable regex patterns, keyword matching, and Shannon entropy analysis
- Dependency vetting against YAML allow/block lists
- Installation script analysis for `setup.py` and `pyproject.toml`
- Configurable detection rules via `risk_patterns.yaml` and `approved_packages.yaml`
- Markdown and JSON report formatters
- Risk explanation generator
- Typer-based CLI with `scan` command
- 72 unit tests and 3 integration tests
- MIT license

[Unreleased]: https://github.com/itsual/sherlockscan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/itsual/sherlockscan/releases/tag/v0.1.0
