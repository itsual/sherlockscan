# Contributing to SherlockScan

Thank you for your interest in improving SherlockScan! This guide covers everything you need to get started.

SherlockScan is a security analysis tool that inspects Python package dependencies for supply-chain risks, hardcoded secrets, and suspicious code patterns. Contributions that sharpen detection accuracy, expand coverage, or improve usability are especially valuable.

## Reporting Bugs

Open an issue at <https://github.com/itsual/sherlockscan/issues> with:

- A clear, descriptive title.
- Steps to reproduce the problem (include the command you ran).
- Expected vs. actual behavior.
- Python version and OS.
- The full error traceback, if applicable.

## Proposing Enhancements

Feature ideas and improvement suggestions are welcome as GitHub issues. Please include:

- A concise description of the enhancement.
- The problem it solves or the use case it enables.
- Any alternative approaches you considered.

## Local Development Setup

```bash
# Clone and enter the repo
git clone https://github.com/itsual/sherlockscan.git
cd sherlockscan

# Create a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install in editable mode with dependencies
pip install -e .
```

Requires **Python 3.8+**.

## Running Tests

Unit tests live in `tests/` and integration tests in `integration/`.

```bash
# Run all unit tests
python -m pytest tests/

# Run integration tests
python -m pytest integration/

# Run a specific test file
python -m pytest tests/test_ast_scanner.py

# Run with verbose output
python -m pytest tests/ -v
```

Make sure all existing tests pass before submitting a pull request.

## Branch and Pull Request Workflow

1. Fork the repository and clone your fork.
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-short-description
   ```
3. Make your changes in focused, logical commits.
4. Push to your fork and open a pull request against `main`.
5. In the PR description, explain **what** changed and **why**.
6. Link any related issues (e.g., "Closes #12").

Keep pull requests focused on a single concern. If you are fixing a bug and adding a feature, split them into separate PRs.

## Code Quality Expectations

- Follow [PEP 8](https://peps.python.org/pep-0008/) style conventions.
- Keep functions small and well-named; prefer clarity over cleverness.
- Avoid adding new dependencies unless genuinely necessary.
- Do not commit secrets, API keys, or credentials (even as test fixtures).
- Remove dead code and debug statements before submitting.

## Adding and Updating Tests

- Every new feature or bug fix should include corresponding tests.
- Tests use Python's `unittest` framework and can be run with `pytest`.
- Place unit tests in `tests/` mirroring the module they cover (e.g., `tests/test_heuristics.py` for `sherlockscan/scanner/heuristics.py`).
- Place end-to-end tests in `integration/`.
- Use descriptive test method names that convey intent (e.g., `test_detects_aws_access_key_in_source`).

## Documentation Updates

- Update `README.md` if your change affects installation, usage, or CLI behavior.
- Add or update docstrings for public functions and classes.
- Keep YAML config files (`sherlockscan/config/`) documented when adding new patterns or rules.

## Respectful Collaboration

- Be kind, constructive, and patient in all interactions.
- Assume good intent when reviewing or receiving feedback.
- Welcome newcomers; no question is too basic.
- Focus critique on the code, not the person.

Thank you for helping make SherlockScan better!
