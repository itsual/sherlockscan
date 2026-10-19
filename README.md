# SherlockScan

[![CI](https://github.com/itsual/sherlockscan/actions/workflows/ci.yml/badge.svg)](https://github.com/itsual/sherlockscan/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sherlockscan.svg)](https://pypi.org/project/sherlockscan/)

SherlockScan is a beta static risk scanner for Python package artifacts. Version
0.3.0 is prepared for release review on `main`; publishing to PyPI is a separate,
manual action. The previously published version remains available until release approval.

**A finding indicates potential risk; it does not prove maliciousness. A clean
scan does not prove safety.**

## Install and run

Python 3.9 or newer is required. For the released version, use `pip install sherlockscan`.
To evaluate the v0.3.0 source before publication:

```bash
git clone https://github.com/itsual/sherlockscan.git
cd sherlockscan
python -m pip install -e ".[dev]"
sherlockscan version
sherlockscan scan ./your-project --format json --output report.json
sherlockscan scan ./package.whl --format sarif --output results.sarif
sherlockscan scan requests==2.32.3 --format md
```

PyPI retrieval chooses a non-yanked wheel compatible with the running interpreter,
or a source archive when no compatible wheel exists. It scans **one exact artifact**,
not every wheel, platform or dependency. The report records its filename and SHA-256.
Artifact hashes from PyPI detect mismatches; they do not establish publisher trust.
For a different platform, supply its wheel explicitly.

## What v0.3.0 does

- Reads ZIP/wheel and TAR source archives without extracting or executing target code.
- Downloads artifact bytes directly from PyPI, without pip or target build hooks.
- Reads declared dependencies from `METADATA`, `PKG-INFO` or static PEP 621 project metadata.
- Inspects Python AST calls, common import aliases, loader arguments and execution context.
- Recognizes startup-executing `.pth` lines and identifies unanalyzed native code.
- Scans source and up to two layers of bounded base64/hex/zlib literal decoding.
- Explains each finding's trigger, legitimate uses and suggested investigation.
- Produces Markdown, JSON, SARIF 2.1.0 and a declared-dependency CycloneDX SBOM.
- Supports scoped suppressions and opt-in CI severity thresholds.

Importing networking or serialization libraries is informational. Co-occurring
environment access and networking is a review hint; no data flow or attack is proven.
`torch.load` checks distinguish explicit unsafe arguments, unknown arguments and
statically constrained PyTorch >=2.6 defaults. Static alias resolution is limited;
reflection, monkey patching, complex control flow and full interprocedural data flow
are outside scope. Severity describes potential impact; confidence describes the
evidence supporting a flag, not a probability that the package is malicious.

## CLI and CI behavior

```bash
sherlockscan scan ./package.whl --fail-on HIGH --severity MEDIUM \
  --suppressions ./reviewed-suppressions.yaml --format json --output report.json \
  --sbom dependencies.cdx.json
```

`--severity` filters displayed details only. Policy evaluates all unsuppressed findings.
Reports retain detected totals, actionable totals, suppression reasons and coverage gaps.
`--include-tests` includes tests, docs and examples, which are excluded and listed by default.
`--no-deobfuscation` disables decoding and explicitly marks that coverage incomplete.
Use `--config DIRECTORY` for trusted custom `risk_patterns.yaml` and optional
`approved_packages.yaml`. Existing v0.2 regex/keyword YAML remains supported. Rules
may supply an uppercase `id`; otherwise a deterministic content-derived ID is used.
Custom patterns are trusted configuration, not sandboxed code or regexes.

| Exit | Meaning |
| --- | --- |
| 0 | Supported checks completed and the configured threshold was not exceeded. No safety guarantee. |
| 10 | Unsuppressed findings exceeded `--fail-on`. |
| 20 | Incomplete coverage: unknown/dynamic metadata, invalid Python, native code or exhausted limits. |
| 30 | Scanner/input/configuration/download/output error; no successful scan verdict. |
| 2 | Invalid command-line usage. |

Incomplete coverage takes precedence over a policy failure; findings remain in the
report. By default findings alone do not fail a completed scan. CI users should set
an appropriate `--fail-on` threshold and treat **every nonzero exit** as requiring review.

Suppressions are only loaded when explicitly supplied by the operator. See
[suppression instructions](docs/suppressions.md) and
[rule guidance](docs/rules.md). Report false positives using the repository issue form
after removing credentials and proprietary source.

## Library API

```python
from sherlockscan.engine import scan_package
from sherlockscan.reporting import render

report = scan_package("./package.whl", fail_on="HIGH")
print(report["status"], report["artifact"], report["coverage"])
print(render(report, "json"))
```

Schema `0.3` retains common v0.2 fields, but adds stable rule IDs, fingerprints,
confidence, suppression state, policy status, artifact identity and coverage. CLI
error/incomplete exit codes have changed intentionally. Legacy low-level scanner
functions remain available for compatibility; `engine.scan_package` is the supported
complete v0.3 pipeline. The legacy `utils.resolve_package_target` also uses static
ingestion; callers must delete its returned temporary directory when finished.

## Limits and review scope

Defaults: compressed artifact 100 MiB, expanded total 250 MiB, each member 25 MiB,
5,000 entries, ZIP ratio 1,000:1, per-source parsing 2 MiB, and a 60-second cooperative
ingestion budget. Decoding uses two transforms and a cumulative 64 KiB budget per
literal. Symlinks, devices, duplicate/case-colliding paths, encrypted ZIP entries and
traversal paths are rejected. Python parsing and regex processing are not an OS-level
sandbox; run investigations of hostile artifacts in an isolated environment.

Static metadata can be missing or incomplete. Optional extras and environment
markers are preserved and inspected as declarations, not resolved for a chosen
runtime. Dependencies are **not recursively audited**, SBOM dependency versions are
not inferred from the scanner host, and native/compiled code is not analyzed.
No automatic installation, package blocking based on co-occurrence, age-based
quarantine, attestation enforcement or typosquatting verdicts are provided.

## Develop and release review

```bash
python -m pytest
python -m ruff check sherlockscan tests integration
python -m build
python -m twine check dist/*
```

See [the release review checklist](docs/release-review.md),
[changelog](CHANGELOG.md), [security policy](SECURITY.md), and
[launch measurement plan](docs/launch-measurement.md).
The manual publishing workflow requires an explicit release-review confirmation.
Pushing to `main` does not publish a package.
