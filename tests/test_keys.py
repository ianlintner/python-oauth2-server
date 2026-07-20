"""`KeySet` unit tests — ported from `crates/oauth2-core/src/models/key_set.rs`
`mod tests` (see `.superpowers/sdd/research-keys-rs256.md` `tests_to_port`).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from oauth2_server.keys import KeySet, SigningKey


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _key(kid: str, algorithm: str, *, is_current: bool = True, expires_at=None) -> SigningKey:
    return SigningKey(
        kid=kid,
        algorithm=algorithm,
        key_material=b"material",
        is_current=is_current,
        created_at=_now(),
        expires_at=expires_at,
    )


def test_current_for_alg_filters_by_algorithm():
    keyset = KeySet()
    keyset.add(_key("hs-1", "HS256", is_current=True))
    keyset.add(_key("rs-1", "RS256", is_current=False))

    assert keyset.current_for_alg("HS256").kid == "hs-1"
    assert keyset.current_for_alg("RS256") is None

    keyset2 = KeySet()
    keyset2.add(_key("hs-1", "HS256", is_current=True))
    keyset2.add(_key("rs-1", "RS256", is_current=True))
    assert keyset2.current_for_alg("RS256").kid == "rs-1"


def test_find_by_kid():
    keyset = KeySet()
    keyset.add(_key("abc", "HS256"))

    assert keyset.find("abc") is not None
    assert keyset.find("abc").kid == "abc"
    assert keyset.find("missing") is None


def test_rotate_marks_old_key_non_current():
    keyset = KeySet()
    keyset.add(_key("old", "HS256", is_current=True))

    new_key = _key("new", "HS256", is_current=True)
    keyset.rotate(new_key, 3600)

    assert keyset.current_for_alg("HS256").kid == "new"

    old = keyset.find("old")
    assert old is not None
    assert old.is_current is False
    assert old.expires_at is not None


def test_prune_expired_removes_old_keys():
    keyset = KeySet()
    keyset.add(_key("expired", "HS256", is_current=False, expires_at=_now() - timedelta(hours=1)))
    keyset.add(_key("current", "HS256", is_current=True))

    pruned = keyset.prune_expired()

    assert pruned == ["expired"]
    assert [k.kid for k in keyset.active_keys()] == ["current"]


def test_active_keys_excludes_expired():
    keyset = KeySet()
    keyset.add(_key("expired", "RS256", is_current=False, expires_at=_now() - timedelta(seconds=1)))
    keyset.add(_key("good", "RS256", is_current=True))

    kids = [k.kid for k in keyset.active_keys()]
    assert kids == ["good"]
