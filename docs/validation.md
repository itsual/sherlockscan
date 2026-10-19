# v0.3.0 implementation validation

Local validation: Windows, Python 3.12.10. Source suite: 149 passing tests, no skips.
The suite includes existing low-level scanner tests and new artifact/CLI/security
regressions. Checks include:

- ZIP/TAR traversal, Windows drive/backslash paths, links/devices, duplicate names,
  count/size/compression limits, and malformed/ambiguous metadata.
- Sdist build hooks and package import side effects never invoked during a scan.
- Host-independent dependency metadata, retained markers/constraints/extras, and
  local project metadata taking precedence over stale generated metadata.
- Alias resolution, lexical shadowing, execution context and PyTorch/NumPy options.
- Bounded nested decoding, payload matches beyond the display-preview boundary,
  credential redaction, incomplete coverage and policy/display independence.
- Exact-path/fingerprint suppressions, expiry, reasons and target-policy isolation.
- CLI errors/output failures, Markdown/JSON, offline OASIS SARIF schema validation,
  and manual-only publishing with release_reviewed=false by default.

Both wheel and source distribution build and pass `twine check`. The installation
smoke script installs each outside the checkout and verifies version, configuration
resources, the library API, report formats and the generated CLI entry point.

An additional live download scan of requests==2.32.3 completed using its own artifact
metadata. A repository self-scan completed, and its SARIF was validated. These are
functional checks; they are not malware-detection precision/recall measurements.

CI additionally runs Python 3.9–3.14 on Linux and Windows and Python 3.12–3.14 on
macOS, including installed-distribution smoke tests. Read the workflow results for
the reviewed commit; local Windows tests alone do not establish those outcomes.

No PyPI release is performed by these checks. Review artifacts can be generated
locally with `python -m build`; publication remains a separate maintainer decision.
