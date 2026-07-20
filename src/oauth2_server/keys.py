"""In-memory signing-key set — RS256/HS256 key rotation and JWKS material.

Ported from `crates/oauth2-core/src/models/key_set.rs`. Rotation state lives
only in `KeySet` (a plain in-process object, not persisted) — the Rust
`signing_keys` DB table is unused by any Rust code path and is intentionally
not replicated here; see `.superpowers/sdd/research-keys-rs256.md` gotchas.
The admin rotate endpoint (`routes/admin/keys.py`) says so explicitly in its
response `warning` field.
"""

from __future__ import annotations

import base64
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel

if TYPE_CHECKING:
    from oauth2_server.config import Config


class SigningKey(BaseModel):
    kid: str
    algorithm: str  # "HS256" | "RS256"
    # HS256: raw secret bytes. RS256: a PKCS#8 PEM-encoded private key.
    key_material: bytes
    is_current: bool = True
    created_at: datetime
    expires_at: datetime | None = None

    def is_active(self) -> bool:
        return self.expires_at is None or datetime.now(timezone.utc) < self.expires_at


class KeySet:
    """In-memory, insertion-ordered collection of `SigningKey`s.

    Mirrors the Rust `KeySet` (a `Vec<SigningKey>` behind an `RwLock` at the
    call site — see `app.state.keyset`, mutated directly since Python's
    async model doesn't need an explicit lock for these synchronous methods).
    """

    def __init__(self) -> None:
        self._keys: list[SigningKey] = []

    def add(self, key: SigningKey) -> None:
        self._keys.append(key)

    def current_for_alg(self, alg: str) -> SigningKey | None:
        for key in self._keys:
            if key.algorithm == alg and key.is_current and key.is_active():
                return key
        return None

    def find(self, kid: str) -> SigningKey | None:
        """Look up a key by `kid`. Expired keys are invisible here even
        before `prune_expired` physically removes them (Rust parity)."""
        for key in self._keys:
            if key.kid == kid and key.is_active():
                return key
        return None

    def active_keys(self) -> list[SigningKey]:
        return [key for key in self._keys if key.is_active()]

    def rotate(self, new_key: SigningKey, grace_secs: int) -> None:
        """Mark every current key sharing `new_key`'s algorithm as
        non-current with `expires_at = now + grace_secs`, then add
        `new_key` (expected `is_current=True`)."""
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=grace_secs)
        for key in self._keys:
            if key.algorithm == new_key.algorithm and key.is_current:
                key.is_current = False
                key.expires_at = expires_at
        self.add(new_key)

    def prune_expired(self) -> list[str]:
        """Physically remove keys that are no longer active. Returns the
        pruned kids. Rust parity: this is the only place pruning happens —
        no background timer."""
        pruned = [key.kid for key in self._keys if not key.is_active()]
        if pruned:
            self._keys = [key for key in self._keys if key.is_active()]
        return pruned


def generate_signing_key(algorithm: str, kid: str) -> SigningKey:
    """Generate fresh key material for `algorithm` ("HS256" | "RS256")."""
    if algorithm == "HS256":
        material = secrets.token_bytes(48)
    elif algorithm == "RS256":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        material = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    return SigningKey(
        kid=kid,
        algorithm=algorithm,
        key_material=material,
        is_current=True,
        created_at=datetime.now(timezone.utc),
    )


def _uint_to_b64url(value: int) -> str:
    """RFC 7518 §6.3.1.1 — big-endian, base64url, no padding."""
    length = max((value.bit_length() + 7) // 8, 1)
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def jwk_from_rs256_key(key: SigningKey) -> dict:
    """Build a public JWK (RFC 7517) from an RS256 `SigningKey`'s private
    PEM. Never emits the private key material itself."""
    private_key = serialization.load_pem_private_key(key.key_material, password=None)
    numbers = private_key.public_key().public_numbers()
    return {
        "kid": key.kid,
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": _uint_to_b64url(numbers.n),
        "e": _uint_to_b64url(numbers.e),
    }


def seed_keyset(config: "Config") -> KeySet:
    """Build the startup `KeySet`: always an HS256 key derived from
    `config.jwt_secret` (kid `"hs256-initial"`), plus an RS256 key from
    `config.id_token_private_key_pem` (kid `config.id_token_kid` or
    `"rs256-initial"`) when that PEM is configured."""
    keyset = KeySet()
    now = datetime.now(timezone.utc)
    keyset.add(
        SigningKey(
            kid="hs256-initial",
            algorithm="HS256",
            key_material=config.jwt_secret.encode(),
            is_current=True,
            created_at=now,
        )
    )
    if config.id_token_private_key_pem:
        keyset.add(
            SigningKey(
                kid=config.id_token_kid or "rs256-initial",
                algorithm="RS256",
                key_material=config.id_token_private_key_pem.encode(),
                is_current=True,
                created_at=now,
            )
        )
    return keyset
