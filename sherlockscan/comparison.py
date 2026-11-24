"""Compare scan results for two artifacts of the same project."""

from __future__ import annotations

from collections import defaultdict
from packaging.utils import canonicalize_name

from .engine import scan_package


def _match_key(finding, report):
    path = finding["file_path"]
    prefix, sep, relative = path.partition("/")
    version = report["package_version"]
    if (
        sep
        and version
        and canonicalize_name(prefix) == canonicalize_name(f"{report['package_name']}-{version}")
    ):
        path = relative
    if path == report["metadata_source"]:
        path = "<metadata>"
    return (
        finding["rule_id"],
        path,
        finding.get("cell_index"),
        finding.get("severity"),
        finding.get("execution_context"),
        finding.get("code_snippet"),
        finding.get("message"),
    )


def _groups(report):
    groups = defaultdict(list)
    for finding in report["findings"]:
        groups[_match_key(finding, report)].append(finding)
    return groups


def _requirements(report):
    pairs = {("", requirement) for requirement in report["requirements"]}
    for group, requirements in report["optional_dependencies"].items():
        pairs.update((group, requirement) for requirement in requirements)
    return pairs


def compare_reports(before, after):
    names = [report["package_name"] for report in (before, after)]
    if "unknown" not in names and canonicalize_name(names[0]) != canonicalize_name(names[1]):
        raise ValueError("Comparison targets must be artifacts of the same project")
    old_groups, new_groups = _groups(before), _groups(after)
    added, removed = [], []
    matched = 0
    for key in dict.fromkeys([*old_groups, *new_groups]):
        old, new = old_groups[key], new_groups[key]
        common_count = min(len(old), len(new))
        matched += common_count
        removed.extend(old[common_count:])
        added.extend(new[common_count:])

    def scan_details(report):
        return {
            key: report[key] for key in ("package_name", "package_version", "artifact", "status", "coverage")
        }

    def describe(requirements):
        return [
            {"extra": group or None, "requirement": requirement}
            for group, requirement in sorted(requirements)
        ]

    old_requirements, new_requirements = _requirements(before), _requirements(after)
    complete = all(report["coverage"]["complete"] for report in (before, after))
    return {
        "schema_version": "1",
        "before": scan_details(before),
        "after": scan_details(after),
        "status": "COMPLETE" if complete else "INCOMPLETE",
        "exit_code": 0 if complete else 20,
        "added_findings": added,
        "removed_findings": removed,
        "matched_findings": matched,
        "added_requirements": describe(new_requirements - old_requirements),
        "removed_requirements": describe(old_requirements - new_requirements),
    }


def compare_targets(before, after, **scan_options):
    return compare_reports(scan_package(before, **scan_options), scan_package(after, **scan_options))
