"""Shared length / nesting-depth guards for JSON-valued request parameters.

Phase 4c residual hardening: several endpoints accept attacker-controlled
JSON in a form or query parameter (`claims`, `authorization_details`, …).
Handing those straight to `json.loads` lets a small request body blow the
interpreter stack (`RecursionError` → unhandled 500) or allocate a deeply
nested structure that later walks recurse over. These helpers centralize the
two cheap guards — raw length first, then an ITERATIVE depth walk — so every
call site rejects the same shapes with the same wording.

Nothing here is wired into a call site yet (that lands with the per-endpoint
limits task); this module only provides the primitives.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

__all__ = ["LimitError", "check_depth", "check_json_param", "check_len"]


class LimitError(Exception):
    """A request parameter exceeded a configured size/depth limit.

    Carries `.description` — the client-facing `error_description` text —
    so call sites can map it onto their own OAuth error code (the right
    code differs per endpoint: `invalid_request` vs
    `invalid_authorization_details`, …).
    """

    def __init__(self, description: str) -> None:
        super().__init__(description)
        self.description = description


def check_len(raw: str, *, name: str, max_len: int, unit: str = "characters") -> str:
    """Return `raw` unchanged, or raise `LimitError` when it is too long.

    `unit` only spells the message ("characters" / "bytes"); the comparison
    is always on `len(raw)`, i.e. Unicode code points.
    """
    if len(raw) > max_len:
        raise LimitError(f"`{name}` exceeds the maximum length of {max_len} {unit}")
    return raw


def check_depth(value: object, *, name: str, max_depth: int) -> None:
    """Raise `LimitError` when `value` nests containers deeper than `max_depth`.

    Deliberately an explicit-stack walk rather than recursion: the input is
    attacker-controlled and already parsed, so a recursive checker would
    itself be the stack overflow it is meant to prevent. Depth counts
    containers only — a scalar is depth 0, `{"a": 1}` is depth 1,
    `{"a": {"b": 1}}` is depth 2.
    """
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Iterable[object] = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > max_depth:
            raise LimitError(f"`{name}` exceeds the maximum nesting depth of {max_depth}")
        stack.extend((child, depth + 1) for child in children)


def check_json_param(raw: str, *, name: str, max_len: int, max_depth: int) -> object:
    """Length-check, parse and depth-check one JSON-valued parameter.

    Order matters: the RAW string is length-checked before `json.loads` runs,
    so an oversized body is rejected without ever being parsed. `json.loads`
    itself can blow the stack on deeply nested input (CPython's scanner
    recurses), and it raises `RecursionError` rather than a decode error —
    that is exactly the over-nesting case, so it is reported with the same
    depth message the post-parse walk would produce.

    A genuinely malformed (but short and shallow) document is NOT a limit
    failure: `json.JSONDecodeError` propagates so each call site keeps its
    own established invalid-JSON error wording.
    """
    check_len(raw, name=name, max_len=max_len)
    try:
        value = json.loads(raw)
    except RecursionError:
        raise LimitError(f"`{name}` exceeds the maximum nesting depth of {max_depth}") from None
    check_depth(value, name=name, max_depth=max_depth)
    return value
