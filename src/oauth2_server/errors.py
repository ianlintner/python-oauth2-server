"""RFC 6749 §5.2 token endpoint error responses."""

from __future__ import annotations

from fastapi.responses import ORJSONResponse


class OAuthError(Exception):
    """Raised by services to signal an RFC 6749 §5.2 error response."""

    def __init__(self, error: str, description: str | None = None, status: int = 400):
        self.error = error
        self.description = description
        self.status = status
        super().__init__(error)


def oauth_error(error: str, description: str | None = None, status: int = 400) -> ORJSONResponse:
    if error == "invalid_client":
        status = 401
    body: dict[str, str] = {"error": error}
    if description is not None:
        body["error_description"] = description
    headers = {"Cache-Control": "no-store"}
    if error == "invalid_client":
        headers["WWW-Authenticate"] = "Basic"
    return ORJSONResponse(body, status_code=status, headers=headers)
