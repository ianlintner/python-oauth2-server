"""Pagination primitives shared by the admin list/page storage methods.

Field-for-field port of the Rust `ListQuery` / `Page` types
(crates/oauth2-ports/src/pagination.rs): a `limit` capped at 200 (default 25
when unset), `sort_by` validated against a per-entity whitelist (never
interpolate caller-provided column names directly into SQL), and a
`{"items", "total", "limit", "offset"}` response envelope.
"""

from __future__ import annotations

from dataclasses import dataclass

_DEFAULT_LIMIT = 25
_MAX_LIMIT = 200


@dataclass
class ListQuery:
    limit: int | None = None
    offset: int = 0
    sort_by: str | None = None
    sort_dir: str = "desc"
    search: str | None = None
    status: str | None = None

    def effective_limit(self) -> int:
        limit = self.limit if self.limit is not None else _DEFAULT_LIMIT
        return min(limit, _MAX_LIMIT)


def page_envelope(items: list, total: int, limit: int, offset: int) -> dict:
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def whitelist_col(requested: str | None, allowed: list[str]) -> str:
    """Guard an ORDER BY column name against SQL injection.

    Returns `requested` only if it's an exact match in `allowed`; otherwise
    falls back to the last (default) entry in `allowed` — mirrors the Rust
    `whitelist_col` behavior where an absent/unknown `sort_by` defaults to
    `created_at`, which every whitelist lists last.
    """
    if requested in allowed:
        return requested
    return allowed[-1]
