# Changelog

## 0.3.0 — prepared, not published

- Static artifact download and metadata inspection without pip or target build hooks.
- Bounded archives/literal decoding, startup hook inspection, explicit coverage gaps.
- Context-aware AST and model-loader checks with conservative capability findings.
- Stable rule IDs, redacted evidence, explanations, scoped auditable suppressions.
- JSON schema 0.3, Markdown, validated SARIF 2.1.0, artifact SHA-256 identity.
- Direct declared dependency policy and SBOM without using host installed versions.
- CI exit codes 0/10/20/30; display filtering cannot bypass policy.
- Tested package builds and explicit manual release approval before PyPI publishing.

Migration: `scan` and existing report/config options remain. Error exits and incomplete
coverage now differ from v0.2.0; consumers should handle the documented status codes.
Capability imports are informational rather than high-severity attack claims.

## 0.2.0

Initial beta on PyPI: archive checks, AST and heuristic scans, JSON/Markdown, SBOM.
