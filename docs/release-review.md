# v0.3.0 release review

Status: prepared for maintainer review; do not publish until approved.

The shipped offline SARIF schema is from OASIS. Its SHA-256 is
`c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`.

- Review the no-target-execution tests and inspect the direct download/metadata path.
- Review byte/count/time limits, malformed archives, decoding limits and coverage states.
- Review fixture expectations for legitimate SDKs and risky loader/startup behavior.
- Review explanation quality, redaction, suppression policy and JSON/SARIF consumers.
- Confirm supported Python/OS CI jobs and installed wheel/sdist smoke checks pass.
- Review known limitations and exit-code migration in the README.
- Inspect the exact commit intended for release and its distribution metadata.
- Approve release before manually running Publish to PyPI with release_reviewed=true.

Existing v0.2 low-level scanner tests remain; CLI integration tests now exercise real
artifacts instead of asserting calls to the removed installed-environment pipeline.
Fixtures are synthetic and are never executed by the scanner. They test specific
capabilities, not real-world malware detection accuracy. No broad precision/recall
claim is supported without a separately reviewed real-package corpus.

Deferred: installation wrapper, graph-wide policy, version diff, data-flow-based
attack verdicts, release-age policies, attestation enforcement and typosquatting.
