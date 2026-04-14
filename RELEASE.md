# PyPI Release Checklist

Steps to publish a new SherlockScan release to PyPI.

## Pre-release

- [ ] All tests pass: `python -m pytest tests/ integration/ -v`
- [ ] No warnings: `python -W error -m pytest tests/`
- [ ] CI is green on the release branch
- [ ] `CHANGELOG.md` is updated with the new version and date
- [ ] Version bumped in `sherlockscan/__init__.py` (`__version__`)
- [ ] `setup.py` URL uses the real repo URL (not `yourusername`)
- [ ] README renders correctly on GitHub (check Mermaid diagram, code blocks, links)
- [ ] Editable install works: `pip install -e . && sherlockscan --help`

## Build

```bash
# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build source distribution and wheel
python -m build

# Verify package metadata and README rendering
twine check dist/*
```

## Test on TestPyPI

```bash
# Upload to TestPyPI first
twine upload --repository testpypi dist/*

# Test install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ sherlockscan

# Verify CLI works
sherlockscan --help
```

## Publish to PyPI

```bash
# Upload to production PyPI
twine upload dist/*
```

## Post-release

- [ ] Create a GitHub release with tag `v<version>` (e.g., `v0.1.0`)
- [ ] Attach the built wheel and sdist to the GitHub release
- [ ] Verify install from PyPI: `pip install sherlockscan && sherlockscan --help`
- [ ] Announce the release if applicable

## Required Tools

```bash
pip install build twine
```

## PyPI Account Setup

1. Create an account at https://pypi.org/account/register/
2. Enable 2FA
3. Create an API token at https://pypi.org/manage/account/token/
4. Configure `~/.pypirc` or use `TWINE_USERNAME=__token__` and `TWINE_PASSWORD=<your-token>`
