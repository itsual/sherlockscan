# CI and pre-commit

Pin the GitHub Action to a reviewed commit containing `action.yml`. For example,
after checking out your project and building a wheel in a GitHub Actions job:

```yaml
- uses: itsual/sherlockscan@REVIEWED_COMMIT_SHA
  with:
    target: dist/my_package-1.0.0-py3-none-any.whl
    fail-on: HIGH
    format: sarif
    output: results.sarif
```

Supply one exact path per run. Use the output file in a later step and select
`if: always()` for report collection on nonzero scan exits. Use the documented
severities and report formats to match the repository's review policy.

For a local Python project with static metadata, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/itsual/sherlockscan
    rev: REVIEWED_COMMIT_SHA
    hooks:
      - id: sherlockscan
```

The hook scans the project once when relevant files change. It uses the same
exit behavior as the CLI, including exit 20 for incomplete scans. The GitHub
Action and hook are part of the development source and need a commit containing
their definitions before external repos can use them.
