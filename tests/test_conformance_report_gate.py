"""`scripts/check_conformance_report.py`: the CI gate that compares a contract
runner report with the deviations declared in `conformance.yaml`.

The runner's own verdict is all-or-nothing. This gate keeps known gaps visible
(each must be declared with a reason) without letting an undeclared regression
through, and ratchets: a declared deviation that now passes must be removed.
"""

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_conformance_report", ROOT / "scripts" / "check_conformance_report.py"
)
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

MANIFEST = {
    "implementation": "python-oauth2-server",
    "contract": "0.1.0",
    "profiles": ["core"],
    "deviations": [
        {
            "requirement": "RFC8252-7.3-loopback-ipv4-any-port",
            "reason": "port wildcard unsupported",
        },
    ],
}


def _result(sid, outcome, requirements, status="stable"):
    return {"id": sid, "outcome": outcome, "requirements": requirements, "status": status}


def _report(*results, contract="0.1.0", implementation="python-oauth2-server", profile="core"):
    return {
        "contract": contract,
        "implementation": implementation,
        "profile": profile,
        "results": list(results),
    }


PASSING = _result("core.ok", "pass", ["RFC6749-4.1.2-authorization-code-issued"])
KNOWN_FAIL = _result("core.native.v4", "fail", ["RFC8252-7.3-loopback-ipv4-any-port"])


def test_passes_when_only_declared_deviations_fail():
    assert gate.evaluate(MANIFEST, _report(PASSING, KNOWN_FAIL)) == []


def test_deferred_scenarios_never_count_as_failures():
    deferred = _result("core.draft", "deferred", ["RFC6749-5.1-no-store"], status="draft")
    assert gate.evaluate(MANIFEST, _report(PASSING, KNOWN_FAIL, deferred)) == []


def test_undeclared_failure_is_rejected():
    bad = _result("core.new", "fail", ["RFC6749-4.1.3-code-single-use"])
    problems = gate.evaluate(MANIFEST, _report(PASSING, KNOWN_FAIL, bad))
    assert len(problems) == 1
    assert "core.new" in problems[0] and "not declared" in problems[0]


def test_declared_deviation_that_now_passes_is_stale():
    fixed = _result("core.native.v4", "pass", ["RFC8252-7.3-loopback-ipv4-any-port"])
    problems = gate.evaluate(MANIFEST, _report(PASSING, fixed))
    assert len(problems) == 1
    assert "RFC8252-7.3-loopback-ipv4-any-port" in problems[0] and "remove" in problems[0]


def test_declared_deviation_for_an_unknown_requirement_is_stale():
    problems = gate.evaluate(MANIFEST, _report(PASSING))
    assert any("RFC8252-7.3-loopback-ipv4-any-port" in p for p in problems)


def test_failure_is_covered_when_any_of_its_requirements_is_declared():
    multi = _result("core.multi", "fail", ["RFC9999-1-x", "RFC8252-7.3-loopback-ipv4-any-port"])
    assert gate.evaluate(MANIFEST, _report(PASSING, multi)) == []


def test_report_must_match_the_manifest_identity():
    for bad in (
        _report(PASSING, KNOWN_FAIL, contract="0.2.0"),
        _report(PASSING, KNOWN_FAIL, implementation="other"),
        _report(PASSING, KNOWN_FAIL, profile="pkce"),
    ):
        assert gate.evaluate(MANIFEST, bad), bad


def test_a_report_without_any_stable_pass_is_not_evidence():
    only_failing = _report(KNOWN_FAIL)
    problems = gate.evaluate(MANIFEST, only_failing)
    assert any("no passing" in p for p in problems)


def test_contract_may_be_a_full_commit_sha():
    sha = "1ad9330a2954314cda9e2b462e36adaadfcd5061"
    gate.validate_manifest({**MANIFEST, "contract": sha})
    manifest = {**MANIFEST, "contract": sha}
    assert gate.evaluate(manifest, _report(PASSING, KNOWN_FAIL, contract=sha)) == []
    for bad in (sha[:39], sha.upper(), sha + "0"):
        with pytest.raises(gate.GateError):
            gate.validate_manifest({**MANIFEST, "contract": bad})


def test_manifest_is_validated():
    for broken in (
        {**MANIFEST, "contract": "v1"},
        {**MANIFEST, "profiles": []},
        {**MANIFEST, "deviations": [{"requirement": "bad id", "reason": "long enough reason"}]},
        {**MANIFEST, "deviations": [{"requirement": "RFC1-1-x", "reason": "short"}]},
        {k: v for k, v in MANIFEST.items() if k != "implementation"},
    ):
        with pytest.raises(gate.GateError):
            gate.validate_manifest(broken)


def test_main_exit_codes(tmp_path, capsys):
    manifest = tmp_path / "conformance.yaml"
    manifest.write_text(yaml.safe_dump(MANIFEST))
    report = tmp_path / "report.json"

    report.write_text(json.dumps(_report(PASSING, KNOWN_FAIL)))
    assert gate.main([str(manifest), str(report)]) == 0

    report.write_text(
        json.dumps(_report(PASSING, KNOWN_FAIL, _result("core.new", "fail", ["X-1-y"])))
    )
    assert gate.main([str(manifest), str(report)]) == 1
    assert "core.new" in capsys.readouterr().err

    assert gate.main([str(manifest), str(tmp_path / "missing.json")]) == 2
    assert gate.main([]) == 2


def test_the_checked_in_manifest_is_valid():
    manifest = yaml.safe_load((ROOT / "conformance.yaml").read_text())
    gate.validate_manifest(manifest)
    assert manifest["implementation"] == "python-oauth2-server"
    assert manifest["profiles"] == ["core", "token-lifecycle", "oidc-basic"]
    assert manifest["contract"] == "1ad9330a2954314cda9e2b462e36adaadfcd5061"
