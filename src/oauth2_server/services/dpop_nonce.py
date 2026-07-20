"""RFC 9449 §8 stateless DPoP nonce issuer — HMAC time-bucketed nonces plus
the `use_dpop_nonce` challenge response.

Ported from `DpopNonceIssuer::issue`/`verify` and the standalone
`use_dpop_nonce_response` helper
(`crates/oauth2-actix/src/handlers/dpop_nonce.rs`); see
`.superpowers/sdd/research-dpop.md` `storage_methods` (`DpopNonceIssuer`
entry) for the exact wire format and `config_keys` for the secret decoding
order this module reproduces. Nonce issuance is stateless — no DB table, no
in-process store — the nonce itself carries the time bucket and an HMAC tag
so any process holding the shared secret can verify it without shared
state (unlike `DpopReplayStore` in `services/dpop.py`, which does need
per-process memory).

**Typed error kinds, not substring matching** — the Rust `enforce_dpop_nonce`
classifies a verify failure as "stale" vs "forged/malformed" by substring-
matching the inner error's description text (`"expired"` / `"not yet
valid"`), flagged as a fragility gotcha in research-dpop.md. This port
instead raises a typed `DpopNonceError(kind, description)` with
`kind in {"stale", "invalid"}`, so `enforce_dpop_nonce` below branches on
the kind directly.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import secrets
import struct
import time

from fastapi.responses import ORJSONResponse

from oauth2_server.services.dpop import DpopError, DpopValidated

logger = logging.getLogger(__name__)

# Wire format: base64url-no-pad(8-byte BE bucket_id || HMAC-SHA256(secret,
# bucket_bytes)[:16]) — 24 raw bytes, always exactly 32 base64url characters
# (24 * 8 / 6, no padding needed).
_BUCKET_LEN = 8
_TAG_LEN = 16
_NONCE_RAW_LEN = _BUCKET_LEN + _TAG_LEN


class DpopNonceError(Exception):
    """Raised by `DpopNonceIssuer.verify` to signal a rejected nonce.

    `kind` is `"stale"` for a correctly-signed nonce outside the accepted
    bucket window (the caller should get a fresh nonce), or `"invalid"` for
    anything forged or malformed — bad base64, wrong length, or a tag
    mismatch — which `enforce_dpop_nonce` below must NOT reward with a
    fresh nonce (research-dpop.md `key_behaviors`: "a tamperer is NOT
    handed a fresh nonce").
    """

    def __init__(self, kind: str, description: str) -> None:
        self.kind = kind
        self.description = description
        super().__init__(description)


class DpopNonceIssuer:
    """Stateless HMAC time-bucketed DPoP nonce issuer.

    Ported from `DpopNonceIssuer` (`crates/oauth2-actix/src/handlers/
    dpop_nonce.rs`). `issue()` encodes the current time bucket
    (`int(time.time()) // lifetime_secs`, wall clock — matches Rust, which
    uses `SystemTime::now()` rather than a monotonic clock); `verify()`
    accepts the current bucket and the immediately preceding one, so the
    effective acceptance window is `[lifetime_secs, 2 * lifetime_secs)`.
    """

    def __init__(self, secret: bytes, lifetime_secs: int) -> None:
        self._secret = secret
        self._lifetime_secs = max(1, lifetime_secs)

    def _current_bucket(self) -> int:
        return int(time.time()) // self._lifetime_secs

    def _tag_for_bucket(self, bucket_bytes: bytes) -> bytes:
        return hmac.new(self._secret, bucket_bytes, "sha256").digest()[:_TAG_LEN]

    def _encode_bucket(self, bucket_id: int) -> str:
        bucket_bytes = struct.pack(">Q", bucket_id)
        raw = bucket_bytes + self._tag_for_bucket(bucket_bytes)
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def issue(self) -> str:
        """Encode a fresh nonce for the current time bucket."""
        return self._encode_bucket(self._current_bucket())

    def verify(self, nonce: str) -> None:
        """Validate `nonce`. Raises `DpopNonceError` on any rejection."""
        try:
            padded = nonce + "=" * (-len(nonce) % 4)
            raw = base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError) as exc:
            raise DpopNonceError("invalid", "DPoP nonce is not valid base64url") from exc

        if len(raw) != _NONCE_RAW_LEN:
            raise DpopNonceError("invalid", "DPoP nonce has incorrect length")

        bucket_bytes, tag = raw[:_BUCKET_LEN], raw[_BUCKET_LEN:]
        expected_tag = self._tag_for_bucket(bucket_bytes)
        if not hmac.compare_digest(tag, expected_tag):
            raise DpopNonceError("invalid", "DPoP nonce signature mismatch")

        bucket_id = struct.unpack(">Q", bucket_bytes)[0]
        current = self._current_bucket()
        if bucket_id not in (current, current - 1):
            raise DpopNonceError("stale", "DPoP nonce is expired or not yet valid")


def use_dpop_nonce_response(issuer: DpopNonceIssuer, description: str) -> ORJSONResponse:
    """Build the RFC 9449 §8 `use_dpop_nonce` challenge: HTTP 400, a fresh
    `DPoP-Nonce` response header, and a JSON error body."""
    return ORJSONResponse(
        {"error": "use_dpop_nonce", "error_description": description},
        status_code=400,
        headers={"DPoP-Nonce": issuer.issue()},
    )


def enforce_dpop_nonce(validated: DpopValidated, issuer: DpopNonceIssuer) -> ORJSONResponse | None:
    """Gate a validated DPoP proof on carrying a fresh server-issued nonce.

    Ported from `enforce_dpop_nonce` (dpop.rs lines 124-150), called only
    after `client.dpop_nonce_required` has already been checked by the
    caller. Returns a `use_dpop_nonce` challenge response when the proof
    has no nonce or a stale one; returns `None` when the nonce is valid;
    raises `DpopError("invalid_dpop_proof", ...)` when the nonce is forged
    or malformed — deliberately NOT a `use_dpop_nonce` challenge, so a
    tamperer is not handed a fresh nonce to keep guessing against.
    """
    if validated.nonce is None:
        return use_dpop_nonce_response(issuer, "DPoP proof must include a server-issued nonce")

    try:
        issuer.verify(validated.nonce)
    except DpopNonceError as exc:
        if exc.kind == "stale":
            return use_dpop_nonce_response(
                issuer, "DPoP nonce is expired; retry with a fresh nonce"
            )
        raise DpopError("invalid_dpop_proof", exc.description) from exc

    return None


def _decode_b64url_nopad(raw: str) -> bytes:
    padded = raw + "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(padded)


def _decode_b64_std(raw: str) -> bytes:
    padded = raw + "=" * (-len(raw) % 4)
    return base64.b64decode(padded, validate=True)


def _decode_hex64(raw: str) -> bytes | None:
    if len(raw) != 64:
        return None
    return bytes.fromhex(raw)


def decode_dpop_nonce_secret(raw: str | None) -> bytes:
    """Decode `OAUTH2_DPOP_NONCE_SECRET` into a 32-byte HMAC-SHA256 key.

    Tries base64url-no-pad, then standard base64, then hex (only when
    `raw` is exactly 64 characters) — the first decode that succeeds and
    yields exactly 32 bytes wins. An unset, undecodable, or wrong-length
    secret falls back to a random per-process 32-byte key (Rust parity:
    `DpopNonceIssuer::from_env`), but — unlike Rust's silent fallback —
    logs a warning, since a random per-process secret means issued nonces
    are only ever valid on the process that issued them and do not survive
    a restart.
    """
    if raw:
        for decode in (_decode_b64url_nopad, _decode_b64_std, _decode_hex64):
            try:
                candidate = decode(raw)
            except (binascii.Error, ValueError):
                continue
            if candidate is not None and len(candidate) == 32:
                return candidate

    logger.warning(
        "OAUTH2_DPOP_NONCE_SECRET is unset or does not decode to 32 bytes "
        "(tried base64url, standard base64, hex); falling back to a random "
        "per-process secret. Nonces issued by this process will not "
        "verify after a restart or on any other instance — set "
        "OAUTH2_DPOP_NONCE_SECRET explicitly for multi-instance deployments."
    )
    return secrets.token_bytes(32)
