# Reviewed suppressions

Use an operator-controlled file outside the scanned package and pass it explicitly:

```yaml
schema_version: 1
suppressions:
  - rule_id: SHLK-EXEC
    path: src/expression_engine.py
    reason: Reviewed evaluator accepts only expressions from our trusted generator.
    expires: '2027-01-01'
```

`sherlockscan scan ./project --suppressions ./reviewed.yaml --fail-on HIGH`

Use the exact relative POSIX path shown in the report. Wildcards and parent paths
are rejected. Instead of `path`, supply a report's 64-character `fingerprint` to
scope an exception to specific evidence. Supplying both requires both to match.
Rule IDs must be exact and every entry needs a nonempty reason. Expiry is optional;
an expiry date remains valid through that local calendar date. Expired/unmatched
entries generate warnings. Suppressions do not hide findings or repair coverage
gaps. They only remove matched findings from the actionable policy count. SARIF
records an accepted external suppression and its reason.

Fingerprints use the rule, relative path, and normalized evidence. Repeated findings
and hidden evidence can include the source position so one fingerprint matches only
one finding. Notebook fingerprints also include the cell number. Moving these
findings can require re-review. Refresh v0.3 fingerprints for redacted findings
after upgrading. Exact-path exceptions cover every match for the chosen rule in
that file.

Never post real secrets in suppression reasons, issue bodies or configuration names.
