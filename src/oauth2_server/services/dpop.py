"""RFC 9449 DPoP (Demonstrating Proof of Possession) — proof-JWT validation
and single-process replay store.

Ported from `validate_dpop_proof` and `DpopReplayStore`
(`crates/oauth2-actix/src/handlers/dpop.rs` lines 21-239); see
`.superpowers/sdd/research-dpop.md` `key_behaviors` for the exact
validation order and error-description strings this module reproduces
verbatim. This module only covers proof validation + replay detection —
nonce issuance (`DpopNonceIssuer`), token-endpoint wiring, and cnf.jkt
binding are separate, later ports.

**Single-process only** — like `ParStore` (services/par.py) and
`FixedWindowLimiter` (services/ratelimit.py), `DpopReplayStore` keeps replay
state in a plain `dict` on the instance, not in the database or a shared
cache. A multi-worker or multi-instance deployment needs this backed by
shared storage (e.g. Redis) instead; the Rust implementation has the same
limitation (its `DpopReplayStore` is an in-process `Arc<Mutex<HashMap>>`
registered once as actix `app_data`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

# +/-5 minutes acceptance window on the proof's `iat` claim (dpop.rs line 55).
DPOP_IAT_SKEW_SECS = 300

# Replay-store entry TTL: 2 * DPOP_IAT_SKEW_SECS + 60s of slack (dpop.rs line
# 232) — a jti must stay rejected for at least as long as a proof could still
# be considered fresh under the iat skew window in either direction.
REPLAY_TTL_SECS = 660

# jsonwebtoken (and thus the Rust validator) cannot verify OKP/EdDSA
# signatures, so those proofs are rejected here too even though PyJWT itself
# could verify them — Rust parity, not a PyJWT limitation.
_ALLOWED_ALGS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"})
_REQUIRED_CLAIMS = ["htm", "htu", "iat", "jti"]


class DpopError(Exception):
    """Raised by `validate_dpop_proof` / `DpopReplayStore` to signal an RFC
    9449 `invalid_dpop_proof` failure."""

    def __init__(self, error: str, description: str) -> None:
        self.error = error
        self.description = description
        super().__init__(description)


@dataclass
class DpopValidated:
    jkt: str
    nonce: str | None


class DpopReplayStore:
    """In-memory `jti` -> monotonic-expiry map guarding against DPoP proof
    replay (RFC 9449 §11.1).

    Ported from `DpopReplayStore::check_and_insert`
    (`crates/oauth2-actix/src/handlers/dpop.rs` lines 21-52), which sweeps
    every expired entry out of the map on each call rather than only
    lazily evicting the key being inserted — see `ParStore._sweep_expired`
    (services/par.py) and `FixedWindowLimiter._sweep_expired`
    (services/ratelimit.py) for the same house pattern. **Single-process
    only**: see module docstring.
    """

    def __init__(self) -> None:
        self._entries: dict[str, float] = {}

    def _sweep_expired(self, now: float) -> None:
        expired = [jti for jti, expiry in self._entries.items() if expiry <= now]
        for jti in expired:
            del self._entries[jti]

    def check_and_insert(self, jti: str) -> None:
        """Sweep expired entries, then record `jti` with a `REPLAY_TTL_SECS`
        expiry. Raises `DpopError` if `jti` is already present (replay)."""
        now = time.monotonic()
        self._sweep_expired(now)
        if jti in self._entries:
            raise DpopError("invalid_dpop_proof", "DPoP proof jti has already been used (replay)")
        self._entries[jti] = now + REPLAY_TTL_SECS


def strip_query(url: str) -> str:
    """Rebuild `url` as `scheme://netloc/path`, dropping the query string
    and fragment, and stripping any trailing slash from the path (RFC 9449
    `htu` comparison; Rust parity, dpop.rs `strip_query` lines 361-365)."""
    parts = urlsplit(url)
    path = parts.path.rstrip("/")
    return f"{parts.scheme}://{parts.netloc}{path}"


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint: canonical JSON (sorted keys, no whitespace)
    of the key type's required members, SHA-256, base64url no padding."""
    kty = jwk.get("kty")
    try:
        if kty == "EC":
            subset = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
        elif kty == "RSA":
            subset = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
        elif kty == "OKP":
            subset = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
        else:
            raise DpopError("invalid_dpop_proof", "Unsupported JWK key type")
    except KeyError as exc:
        raise DpopError("invalid_dpop_proof", "Unsupported JWK key type") from exc

    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _build_verification_key(alg: str, jwk: dict):
    """Build a PyJWT verification key from the proof's embedded JWK. Only
    called once `alg` has already been checked against `_ALLOWED_ALGS`, so
    it is always RS*/PS* (RSA) or ES* (EC)."""
    if alg.startswith("RS") or alg.startswith("PS"):
        return RSAAlgorithm.from_jwk(jwk)
    return ECAlgorithm.from_jwk(jwk)


def validate_dpop_proof(
    proof: str, method: str, url: str, replay_store: DpopReplayStore
) -> DpopValidated:
    """Validate a DPoP proof JWT per RFC 9449 §4.3.

    Ported verbatim (order + error strings) from `validate_dpop_proof`
    (`crates/oauth2-actix/src/handlers/dpop.rs` lines 164-239); see
    `.superpowers/sdd/research-dpop.md` `key_behaviors`. Validation order:
    header parse -> typ -> jwk presence -> thumbprint -> signature (with
    htm/htu/iat/jti required, aud/exp unchecked) -> htm match -> htu match
    -> iat skew -> jti replay.
    """
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.exceptions.DecodeError as exc:
        raise DpopError("invalid_dpop_proof", "DPoP proof header is malformed") from exc

    typ = str(header.get("typ") or "")
    if typ.lower() != "dpop+jwt":
        raise DpopError("invalid_dpop_proof", 'DPoP proof typ must be "dpop+jwt"')

    jwk = header.get("jwk")
    if not jwk:
        raise DpopError("invalid_dpop_proof", "DPoP proof missing 'jwk' header claim")

    jkt = jwk_thumbprint(jwk)

    alg = header.get("alg")
    if alg not in _ALLOWED_ALGS:
        raise DpopError(
            "invalid_dpop_proof",
            "DPoP proof uses unsupported algorithm (only RS256/RS384/RS512/"
            "PS256/PS384/PS512/ES256/ES384 allowed)",
        )

    try:
        verify_key = _build_verification_key(alg, jwk)
        claims = jwt.decode(
            proof,
            key=verify_key,
            algorithms=[alg],
            options={
                "require": _REQUIRED_CLAIMS,
                "verify_aud": False,
                "verify_exp": False,
            },
        )
    except Exception as exc:
        raise DpopError("invalid_dpop_proof", f"DPoP proof signature invalid: {exc}") from exc

    htm = str(claims.get("htm") or "")
    if htm.lower() != method.lower():
        raise DpopError("invalid_dpop_proof", "DPoP proof htm does not match request method")

    if strip_query(str(claims.get("htu") or "")) != strip_query(url):
        raise DpopError("invalid_dpop_proof", "DPoP proof htu does not match request URI")

    try:
        iat = float(claims["iat"])
    except (TypeError, ValueError) as exc:
        raise DpopError(
            "invalid_dpop_proof", "DPoP proof iat is outside the acceptance window"
        ) from exc
    if not (-DPOP_IAT_SKEW_SECS <= (time.time() - iat) <= DPOP_IAT_SKEW_SECS):
        raise DpopError("invalid_dpop_proof", "DPoP proof iat is outside the acceptance window")

    replay_store.check_and_insert(str(claims["jti"]))

    return DpopValidated(jkt=jkt, nonce=claims.get("nonce"))
