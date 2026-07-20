"""Small shared helpers for the admin JSON API handlers.

Split out from `clients.py`/`users.py` (rather than living in
`routes/admin/__init__.py`) because `__init__.py` imports both of those
modules at import time to build `admin_router`; having them import back
from `__init__.py` would create a circular import.
"""

from __future__ import annotations

from fastapi import Request


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
