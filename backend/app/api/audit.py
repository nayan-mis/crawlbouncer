"""Read-only publisher audit trail."""
import json
from fastapi import APIRouter, Depends, Query
from app.api.auth import require_auth
from app.database import get_db

router = APIRouter(prefix="/api/audit", tags=["audit"])

@router.get("/")
def list_events(limit: int = Query(50, ge=1, le=200), auth: dict = Depends(require_auth)):
    with get_db() as db:
        rows = db.execute("""SELECT id, action, resource_type, resource_id, details, created_at
            FROM audit_events WHERE publisher_id=? ORDER BY id DESC LIMIT ?""", (auth["sub"], limit)).fetchall()
    return [{**dict(row), "details": json.loads(row["details"] or "{}")} for row in rows]
