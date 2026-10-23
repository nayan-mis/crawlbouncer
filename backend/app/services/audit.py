"""Append-only audit events for security-sensitive publisher actions."""
import json
from app.database import get_db

def record(publisher_id: str, actor_id: str, action: str, resource_type: str = "", resource_id: str = "", details: dict | None = None) -> None:
    with get_db() as db:
        db.execute("""INSERT INTO audit_events
            (publisher_id, actor_id, action, resource_type, resource_id, details)
            VALUES (?,?,?,?,?,?)""",
            (publisher_id, actor_id, action, resource_type, resource_id, json.dumps(details or {}, separators=(",", ":"))),
        )
