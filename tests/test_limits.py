"""`services/limits.py` — shared length/nesting-depth guards for JSON-valued
request parameters (Phase 4c Task 1 infrastructure).

These are pure unit tests: the helpers are NOT yet wired into any call site
(that is Task 8), so nothing here drives an endpoint.
"""

from __future__ import annotations

import json

import pytest

from oauth2_server.services.limits import LimitError, check_depth, check_json_param, check_len


def test_check_len_returns_raw_when_within_limit():
    assert check_len("abc", name="claims", max_len=3) == "abc"


def test_check_len_raises_with_exact_message():
    with pytest.raises(LimitError) as exc:
        check_len("abcd", name="claims", max_len=3)
    assert exc.value.description == "`claims` exceeds the maximum length of 3 characters"
    assert str(exc.value) == exc.value.description


def test_check_len_honors_custom_unit():
    with pytest.raises(LimitError) as exc:
        check_len("abcd", name="authorization_details", max_len=3, unit="bytes")
    assert exc.value.description == "`authorization_details` exceeds the maximum length of 3 bytes"


def test_check_depth_accepts_nested_dict_within_limit():
    value = {"a": {"b": {"c": 1}}}
    assert check_depth(value, name="claims", max_depth=3) is None


def test_check_depth_raises_on_nested_dict_over_limit():
    value = {"a": {"b": {"c": {"d": 1}}}}
    with pytest.raises(LimitError) as exc:
        check_depth(value, name="claims", max_depth=3)
    assert exc.value.description == "`claims` exceeds the maximum nesting depth of 3"


def test_check_depth_ignores_scalars():
    assert check_depth("plain", name="claims", max_depth=1) is None
    assert check_depth(5, name="claims", max_depth=1) is None


def test_check_json_param_returns_parsed_value():
    assert check_json_param('{"a": [1, 2]}', name="claims", max_len=100, max_depth=5) == {
        "a": [1, 2]
    }


def test_check_json_param_checks_length_before_parsing():
    # Invalid JSON that is also over-length must report the LENGTH error:
    # the raw string is checked before `json.loads` ever runs.
    with pytest.raises(LimitError) as exc:
        check_json_param("{{{{{{", name="claims", max_len=3, max_depth=10)
    assert exc.value.description == "`claims` exceeds the maximum length of 3 characters"


def test_check_json_param_rejects_fifty_deep_array():
    raw = "[" * 50 + "]" * 50
    with pytest.raises(LimitError) as exc:
        check_json_param(raw, name="authorization_details", max_len=10_000, max_depth=10)
    assert (
        exc.value.description == "`authorization_details` exceeds the maximum nesting depth of 10"
    )


def test_check_json_param_accepts_depth_at_the_limit():
    raw = "[" * 10 + "]" * 10
    assert check_json_param(raw, name="claims", max_len=10_000, max_depth=10) is not None


def test_check_json_param_survives_hundred_thousand_deep_string():
    # `json.loads` blows the C/Python stack on deeply nested input; the guard
    # must surface a LimitError, never a RecursionError escaping to a 500.
    raw = "[" * 100_000 + "]" * 100_000
    with pytest.raises(LimitError) as exc:
        check_json_param(raw, name="claims", max_len=1_000_000, max_depth=10)
    assert exc.value.description == "`claims` exceeds the maximum nesting depth of 10"


def test_check_json_param_propagates_invalid_json():
    # Malformed (but short and shallow) JSON is NOT a limit failure — call
    # sites keep their own invalid-JSON error messages (Task 8).
    with pytest.raises(json.JSONDecodeError):
        check_json_param("not json", name="claims", max_len=100, max_depth=10)
