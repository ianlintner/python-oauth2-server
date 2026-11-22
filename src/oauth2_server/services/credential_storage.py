"""At-rest representation of credentials and token lookups.

Threat model: a copy of the database (backup, replica, snapshot, a read-only
operator grant) must not be directly usable as a credential against this
server or its clients. Three different kinds of stored value need three
different treatments:

*Lookup credentials* — values the server receives and must find a row for:
access tokens, refresh tokens, authorization codes, device codes and
registration access tokens. They are high entropy (``secrets.token_urlsafe(32)``
= 256 bits, or a JWT), so a fast one-way, domain-separated SHA-256 digest is
enough; the digest is the lookup key. Lookups ALWAYS digest the presented
value (`digest`), so presenting a stored digest as if it were the credential
matches nothing. Only writes use the idempotent `at_rest`, so re-saving a row
read back from storage never double-hashes.

*Comparison-only credentials* — client secrets under ``client_secret_basic`` /
``client_secret_post``. Stored as an Argon2id verifier (`secret_verifier`),
which is nonrecoverable.

*Symmetric key material* — ``client_secret_jwt`` (RFC 7523), JAR with an HMAC
algorithm and HS256 JWT introspection responses use the client secret as an
HMAC key, which a verifier cannot give back. That one value is stored
separately as sealed key material (`seal`: AES-256-GCM, key derived from
server configuration, bound to the ``client_id`` as AAD) in
``clients.client_secret_key`` and is unsealed in memory only. This is a
deliberate, narrower exposure than plaintext: a database copy alone is useless,
but the server key plus the database recovers the secret. See
`docs/credential-cutover.md`.

Nothing in this module logs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re

from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- lookup-credential digests -------------------------------------------------

DIGEST_KINDS = ("access", "refresh", "authcode", "device", "rat")

_DIGEST_PREFIX = "sha256-"
_DIGEST_VERSION = "v1"
_HASH_SEP = "$"
_B64_LEN = 43  # base64url, no padding, of a 32-byte SHA-256 output


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def digest_tag(kind: str) -> str:
    """Stored prefix identifying a digest of ``kind``: ``sha256-access-v1$``."""
    if kind not in DIGEST_KINDS:
        raise ValueError(f"unknown digest kind: {kind!r}")
    return f"{_DIGEST_PREFIX}{kind}-{_DIGEST_VERSION}{_HASH_SEP}"


def digest(value: str, kind: str) -> str:
    """At-rest digest of a presented lookup credential (always hashes)."""
    return digest_tag(kind) + _b64url(hashlib.sha256(value.encode("utf-8")).digest())


def _matches_kind(stored: str, kind: str) -> bool:
    tag = digest_tag(kind)
    if not stored.startswith(tag) or len(stored) != len(tag) + _B64_LEN:
        return False
    try:
        return len(_unb64url(stored[len(tag) :])) == 32
    except ValueError:
        return False


def is_digest(stored: str, kind: str | None = None) -> bool:
    """Whether ``stored`` is a digest in the current format (of ``kind`` if given)."""
    if kind is not None:
        return _matches_kind(stored, kind)
    return any(_matches_kind(stored, k) for k in DIGEST_KINDS)


def at_rest(value: str, kind: str) -> str:
    """WRITE-path form: ``value`` digested, unless it already is a digest of
    ``kind`` (idempotent re-save). Never use this on a lookup path."""
    return value if is_digest(value, kind) else digest(value, kind)


def is_legacy(stored: str | None, kind: str) -> bool:
    """Whether ``stored`` is a pre-cutover raw value (present, not a digest)."""
    return bool(stored) and not is_digest(stored, kind)


# --- client secret verifier ---------------------------------------------------

_SECRET_TAG = "argon2id-v1$"  # nosec B105 - format tag, not a password

# Verification runs on every client-authenticated request; raise the cost only
# against a measured latency budget.
_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16)


def secret_verifier(value: str) -> str:
    """Nonrecoverable at-rest verifier of a client secret."""
    return _SECRET_TAG + _HASHER.hash(value)


# ``extract_parameters`` only counts base64 characters and parses the numeric
# fields; it does not reject malformed alphabet characters. Check the complete
# canonical v1 encoding so a legacy plaintext secret that merely looks like an
# Argon2id header can never be misclassified as already converted.
_VERIFIER_BODY = re.compile(
    r"^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+={0,2})\$([A-Za-z0-9+/]+={0,2})$"
)


def is_secret_verifier(stored: str | None) -> bool:
    """Whether ``stored`` is a well-formed verifier: the tag followed by a
    parseable Argon2id encoding. A bare prefix or a malformed salt/hash is NOT
    enough: a legacy plaintext secret with that shape must still be classed
    (and converted) as legacy rather than silently counted as converted."""
    if not stored or not stored.startswith(_SECRET_TAG):
        return False
    body = stored[len(_SECRET_TAG) :]
    match = _VERIFIER_BODY.fullmatch(body)
    if match is None:
        return False
    version, memory, time_cost, parallelism, salt, digest_b64 = match.groups()
    if (
        int(version) != 19
        or int(memory) <= 0
        or int(time_cost) <= 0
        or int(parallelism) <= 0
        or len(_unb64url(salt)) < 8
        or len(_unb64url(digest_b64)) < 16
    ):
        return False
    try:
        params = extract_parameters(body)
    except (InvalidHashError, ValueError):
        return False
    return params.type == Type.ID


def is_legacy_secret(stored: str | None) -> bool:
    """A stored client secret that is present but not a verifier (pre-cutover)."""
    return bool(stored) and not is_secret_verifier(stored)


def verify_client_secret(stored: str, presented: str) -> bool:
    """Check ``presented`` against a stored verifier. A legacy plaintext row
    NEVER verifies — there is no silent legacy acceptance after cutover."""
    if not is_secret_verifier(stored) or not presented:
        return False
    try:
        return _HASHER.verify(stored[len(_SECRET_TAG) :], presented)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# --- sealed symmetric key material --------------------------------------------

_SEAL_TAG = "aesgcm-v1$"
_SEAL_INFO = b"oauth2-server/client-secret-key/v1"


class SealError(ValueError):
    """Raised when sealed key material cannot be opened (wrong server key,
    wrong client binding, or tampering). Never carries the value."""


def derive_seal_key(master: str) -> bytes:
    """32-byte AES key derived from the configured server secret (HKDF-SHA256)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_SEAL_INFO).derive(
        master.encode("utf-8")
    )


def seal(value: str, key: bytes, client_id: str) -> str:
    """Seal ``value`` as AES-256-GCM key material bound to ``client_id``."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, value.encode("utf-8"), client_id.encode("utf-8"))
    return _SEAL_TAG + _b64url(nonce + ct)


def is_sealed(stored: str | None) -> bool:
    return bool(stored) and stored.startswith(_SEAL_TAG)


def unseal(stored: str, key: bytes, client_id: str) -> str:
    if not is_sealed(stored):
        raise SealError("not sealed key material")
    try:
        raw = _unb64url(stored[len(_SEAL_TAG) :])
        return AESGCM(key).decrypt(raw[:12], raw[12:], client_id.encode("utf-8")).decode("utf-8")
    except (InvalidTag, ValueError) as exc:
        raise SealError("sealed key material could not be opened") from exc


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
