import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from oauth2_server.models import Claims, IdTokenClaims

_hasher = PasswordHasher()


def encode_access_token(claims: Claims, secret: str) -> str:
    return jwt.encode(claims.to_payload(), secret, algorithm="HS256", headers={"typ": "at+JWT"})


def encode_id_token(claims: IdTokenClaims, secret: str) -> str:
    return jwt.encode(claims.model_dump(exclude_none=True), secret, algorithm="HS256")


def decode_access_token(token: str, secret: str, issuer: str) -> Claims:
    payload = jwt.decode(
        token, secret, algorithms=["HS256"], issuer=issuer, options={"verify_aud": False}
    )
    aud = payload.get("aud")
    if isinstance(aud, str):
        payload["aud"] = [aud]
    return Claims(**payload)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, phc_hash: str) -> bool:
    try:
        return _hasher.verify(phc_hash, password)
    except VerifyMismatchError:
        return False
