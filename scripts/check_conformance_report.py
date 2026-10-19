#!/usr/bin/env python3
"""Gate a contract-runner report against the deviations in `conformance.yaml`.

Usage: check_conformance_report.py <conformance.yaml> <report.json>

The runner's verdict is all-or-nothing: one failing `stable` scenario makes it
`fail`. This server has known protocol gaps that predate its conformance test
mode, so the manifest declares each as a `deviation` (requirement + reason,
schema: `implementation-manifest.schema.json`) and this gate enforces:

* the report is for this implementation, contract version and a claimed profile;
* every failing scenario is covered by a declared deviation (an undeclared
  failure, i.e. a regression, fails the gate);
* every declared deviation still fails (a deviation that now passes, or names a
  requirement no scenario exercises, is stale and must be removed: the
  ratchet only tightens);
* at least one stable scenario passed (an empty run is not evidence).

`deferred` scenarios (draft / reference-deviation) never count as failures.
Exit codes: 0 gate passed, 1 gate failed, 2 usage or unreadable input.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

# `contract` is a tagged MAJOR.MINOR.PATCH or, before that tag exists, the
# full 40-hex commit SHA on the contract's `main` (ROADMAP.md flow step 2).
_SEMVER = re.compile(r"^(?:\d+\.\d+\.\d+|[0-9a-f]{40})$")
_REQUIREMENT_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:[0-9])?-[A-Za-z0-9._-]+$")


class GateError(Exception):
    """Invalid manifest or report."""


def validate_manifest(manifest: object) -> None:
    """The parts of `implementation-manifest.schema.json` this gate relies on."""
    if not isinstance(manifest, dict):
        raise GateError("manifest must be a mapping")
    for key in ("implementation", "contract", "profiles"):
        if key not in manifest:
            raise GateError(f"manifest is missing required key {key!r}")
    if not isinstance(manifest["contract"], str) or not _SEMVER.match(manifest["contract"]):
        raise GateError(
            "manifest contract must be a MAJOR.MINOR.PATCH version or a 40-hex commit SHA"
        )
    profiles = manifest["profiles"]
    if (
        not isinstance(profiles, list)
        or not profiles
        or not all(isinstance(p, str) and p for p in profiles)
    ):
        raise GateError("manifest profiles must be a non-empty list of profile ids")
    for deviation in manifest.get("deviations") or []:
        if not isinstance(deviation, dict):
            raise GateError("each deviation must be a mapping")
        requirement = deviation.get("requirement")
        if not isinstance(requirement, str) or not _REQUIREMENT_ID.match(requirement):
            raise GateError(f"deviation requirement {requirement!r} is not a requirement id")
        reason = deviation.get("reason")
        if not isinstance(reason, str) or len(reason) < 10:
            raise GateError(f"deviation {requirement}: reason must be at least 10 characters")


def evaluate(manifest: dict, report: dict) -> list[str]:
    """Return the list of gate violations (empty means the gate passes)."""
    problems: list[str] = []

    if report.get("contract") != manifest["contract"]:
        problems.append(
            f"report contract {report.get('contract')!r} != pinned {manifest['contract']!r}"
        )
    if report.get("implementation") != manifest["implementation"]:
        problems.append(
            f"report implementation {report.get('implementation')!r} "
            f"!= manifest {manifest['implementation']!r}"
        )
    if report.get("profile") not in manifest["profiles"]:
        problems.append(f"report profile {report.get('profile')!r} is not a claimed profile")

    results = report.get("results") or []
    declared = {d["requirement"] for d in manifest.get("deviations") or []}
    failing_requirements: set[str] = set()

    for result in results:
        requirements = set(result.get("requirements") or [])
        if result.get("outcome") == "fail":
            failing_requirements |= requirements
            if not requirements & declared:
                problems.append(
                    f"scenario {result.get('id')} failed and its requirements "
                    f"{sorted(requirements)} are not declared as deviations"
                )

    for requirement in sorted(declared):
        if requirement not in failing_requirements:
            problems.append(
                f"deviation {requirement} no longer fails (or no scenario exercises it): "
                "remove it from conformance.yaml"
            )

    if not any(r.get("outcome") == "pass" and r.get("status") == "stable" for r in results):
        problems.append("no passing stable scenario: an empty run is not evidence")

    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    manifest_path, report_path = (Path(a) for a in argv)
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        validate_manifest(manifest)
        if not isinstance(report, dict):
            raise GateError("report must be a JSON object")
    except (OSError, yaml.YAMLError, json.JSONDecodeError, GateError) as exc:
        print(f"check_conformance_report: {exc}", file=sys.stderr)
        return 2

    problems = evaluate(manifest, report)
    results = report.get("results") or []
    counts = {
        o: sum(1 for r in results if r.get("outcome") == o) for o in ("pass", "fail", "deferred")
    }
    print(
        f"conformance: {counts['pass']} passed, {counts['fail']} failed "
        f"({len(manifest.get('deviations') or [])} declared deviations), "
        f"{counts['deferred']} deferred"
    )
    for problem in problems:
        print(f"conformance gate: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
