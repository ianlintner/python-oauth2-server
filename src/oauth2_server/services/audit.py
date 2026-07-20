"""Admin mutation audit trail — ported from the Rust `build_audit` /
`record_audit` helpers used throughout `crates/oauth2-actix/src/handlers/
admin_extra.rs`.

Every mutating admin endpoint (Tasks 8-10) builds an `AuditLogEntry` via
`build_audit` and persists+fans-out via `record_audit`. Writing the audit row
is best-effort: a storage failure is logged, never raised, so a flaky audit
backend can't block the admin mutation it's describing.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import Request

from oauth2_server.models import AuditLogEntry
from oauth2_server.routes.admin.guard import AdminActor
from oauth2_server.services.events import RecentEventsStore

logger = logging.getLogger(__name__)


def build_audit(
    request: Request,
    actor: AdminActor,
    action: str,
    target_kind: str,
    target_id: str,
    metadata: dict,
) -> AuditLogEntry:
    return AuditLogEntry(
        id=uuid.uuid4().hex,
        actor_id=actor.actor_id,
        actor_email=actor.actor_email,
        action=action,
        target_kind=target_kind,
        target_id=target_id,
        ip=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
        metadata=json.dumps(metadata),
        created_at=datetime.now(timezone.utc),
    )


async def record_audit(storage, events: RecentEventsStore, entry: AuditLogEntry) -> None:
    try:
        await storage.write_audit_log(entry)
    except Exception:
        logger.warning("failed to write audit log entry action=%s", entry.action, exc_info=True)

    events.push(
        {
            "event_type": entry.action,
            "source": "admin",
            "idempotency_key": entry.id,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "actor_id": entry.actor_id,
            "actor_email": entry.actor_email,
            "target_kind": entry.target_kind,
            "target_id": entry.target_id,
            "metadata": json.loads(entry.metadata) if entry.metadata else {},
        }
    )
