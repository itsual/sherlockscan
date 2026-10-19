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

Fingerprints hash the rule, relative file path and whitespace-normalized evidence;
moving identical evidence to a different line does not invalidate it. Relocating a
file or changing its evidence may require re-review. Exact-path exceptions cover all
matching findings for that rule in that file; use fingerprints for narrower scope.

Never post real secrets in suppression reasons, issue bodies or configuration names.
