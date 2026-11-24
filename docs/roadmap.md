# Development roadmap

The v0.4 development milestone combines notebook code inspection, artifact
comparison, HTML reporting, lightweight model source rules, opt-in dependency
name hints, and CI integration. It also improves suppression granularity, wheel
selection, SBOM dependency links, and missing-target errors.

Next steps should build on fixtures and measured false positives:

- Accept lockfiles as explicit inventory inputs and optionally enrich exact
  versions with OSV results. Keep advisory findings separate from static
  behavior and preserve dependency markers and extras.
- Expand source-tree metadata deliberately, including local requirements files,
  after defining behavior for includes, optional groups, and unsupported syntax.
- Evaluate bounded model-file and native-binary coverage. Add model data-flow
  evidence once representative fixtures establish the precision of the analysis.
- Gather reproducible examples and review suppression migrations before cutting
  a release. Evaluate parallel scanning against measured performance first.
