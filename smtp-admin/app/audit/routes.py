import io
import json
import logging
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from ..common import require_role
from ..config import settings
from datetime import datetime
from ..services.audit_log_service import AuditLogError, audit_log_service

from fastapi.responses import StreamingResponse
# from ..services.audit_log_service import (
#     AuditLogError,
#     read_recent_entries,
#     filter_by_action_keywords,
#     search_entries,
#     read_all_entries,
#     filter_by_date_range,
#     entries_to_csv,
#     entries_to_json,
# )

from ..services.audit_log_service import (
    AuditLogError,
    audit_log_service,

)

logger = logging.getLogger(__name__)

router = APIRouter()

# Keywords assumed present in relevant action names, based on this
# project's UPPER_SNAKE_CASE action naming convention. Adjust if your
# actual action strings differ.
AUTH_ACTION_KEYWORDS = ["LOGIN", "LOGOUT", "AUTH"]
PRIVILEGED_ACTION_KEYWORDS = ["RELOAD", "RESTART", "START", "STOP", "ENABLE", "FLUSH", "DELETE", "CLEAR"]
CONFIGURATION_ACTION_KEYWORDS = ["MAP", "REDIS_CONFIG", "CERTIFICATE", "SUBMISSION"]
POLICY_ACTION_KEYWORDS = ["POLICY", "RECIPIENT", "RELAY", "IP_"]


def get_current_user(request: Request) -> dict:
    """
    Builds the current_user context object used by shared partials
    (topnav.html, sidebar.html). Kept in sync with the same helper
    duplicated across every other router in this app.
    """
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", get_current_user(request))
    return templates.TemplateResponse(request, name, ctx)

def _parse_audit_line(line: str) -> dict:
    """
    Parses one audit log line (expected to be a JSON object per line).
    Falls back to a raw wrapper if a line is malformed, so one bad
    line can't take down the whole audit page.
    """
    try:
        entry = json.loads(line)
        if not isinstance(entry, dict):
            raise ValueError("Audit line did not decode to an object")
        entry["_raw"] = line
        return entry
    except Exception:
        return {
            "_raw": line,
            "_parse_error": True,
        }


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    error = None
    entries = []

    try:
        path = Path(settings.audit_log_path)
        lines = path.read_text(encoding="utf-8").splitlines()[-200:] if path.exists() else []
        entries = [_parse_audit_line(line) for line in reversed(lines)]
    except Exception as exc:
        logger.exception("Failed to read audit log at %s", settings.audit_log_path)
        error = str(exc)

    return render(
        request,
        "audit.html",
        entries=entries,
        error=error,
    )

@router.get("/audit/authentication", response_class=HTMLResponse)
async def audit_authentication_page(request: Request, q: str = ""):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    error = None
    entries = []

    try:
        all_entries = audit_log_service.read_recent_entries( limit=500)
        entries = audit_log_service.filter_by_action_keywords(all_entries, AUTH_ACTION_KEYWORDS)
        entries = audit_log_service.search_entries(entries, q)
    except AuditLogError as exc:
        error = str(exc)

    success_count = sum(1 for e in entries if (e.get("result") or "").upper() == "SUCCESS")
    failed_count = sum(1 for e in entries if (e.get("result") or "").upper() == "FAILED")

    return render(
        request,
        "audit_authentication.html",
        entries=entries,
        success_count=success_count,
        failed_count=failed_count,
        search_query=q,
        error=error,
    )



@router.get("/audit/privileged", response_class=HTMLResponse)
async def audit_privileged_page(request: Request, q: str = ""):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    error = None
    entries = []

    try:
        all_entries = audit_log_service.read_recent_entries(limit=500)
        entries = audit_log_service.filter_by_action_keywords(all_entries, PRIVILEGED_ACTION_KEYWORDS)
        entries = audit_log_service.search_entries(entries, q)
    except AuditLogError as exc:
        error = str(exc)

    success_count = sum(1 for e in entries if (e.get("result") or "").upper() == "SUCCESS")
    failed_count = sum(1 for e in entries if (e.get("result") or "").upper() == "FAILED")

    # Distinct set of actors who performed privileged actions, for a
    # quick "who's been doing high-risk things" summary
    actor_count = len({e.get("username") for e in entries if e.get("username")})

    return render(
        request,
        "audit_privileged.html",
        entries=entries,
        success_count=success_count,
        failed_count=failed_count,
        actor_count=actor_count,
        search_query=q,
        error=error,
    )



@router.get("/audit/configuration", response_class=HTMLResponse)
async def audit_configuration_page(request: Request, q: str = ""):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    error = None
    entries = []

    try:
        all_entries = audit_log_service.read_recent_entries( limit=500)
        entries = audit_log_service.filter_by_action_keywords(all_entries, CONFIGURATION_ACTION_KEYWORDS)
        entries = audit_log_service.search_entries(entries, q)
    except AuditLogError as exc:
        error = str(exc)

    success_count = sum(1 for e in entries if (e.get("result") or "").upper() == "SUCCESS")
    failed_count = sum(1 for e in entries if (e.get("result") or "").upper() == "FAILED")
    object_count = len({e.get("object") for e in entries if e.get("object")})

    return render(
        request,
        "audit_configuration.html",
        entries=entries,
        success_count=success_count,
        failed_count=failed_count,
        object_count=object_count,
        search_query=q,
        error=error,
    )


@router.get("/audit/policies", response_class=HTMLResponse)
async def audit_policies_page(request: Request, q: str = ""):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    error = None
    entries = []

    try:
        all_entries = audit_log_service.read_recent_entries( limit=500)
        entries = audit_log_service.filter_by_action_keywords(all_entries, POLICY_ACTION_KEYWORDS)
        entries = audit_log_service.search_entries(entries, q)
    except AuditLogError as exc:
        error = str(exc)

    success_count = sum(1 for e in entries if (e.get("result") or "").upper() == "SUCCESS")
    failed_count = sum(1 for e in entries if (e.get("result") or "").upper() == "FAILED")

    # Rough breakdown by policy action family, for the chip row
    breakdown: dict = {}
    for e in entries:
        action = (e.get("action") or "unknown").lower()
        if "allowed" in action:
            key = "Allowed"
        elif "denied" in action:
            key = "Denied"
        elif "blocked" in action:
            key = "Blocked"
        elif "relay" in action:
            key = "Relay"
        elif "recipient" in action:
            key = "Recipient"
        else:
            key = "Other"
        breakdown[key] = breakdown.get(key, 0) + 1

    return render(
        request,
        "audit_policies.html",
        entries=entries,
        success_count=success_count,
        failed_count=failed_count,
        breakdown=breakdown,
        search_query=q,
        error=error,
    )

@router.get("/audit/export", response_class=HTMLResponse)
async def audit_export_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    error = None
    total_entries = 0

    try:
        total_entries = len(audit_log_service.read_recent_entries(limit=500))
    except AuditLogError as exc:
        error = str(exc)

    return render(
        request,
        "audit_export.html",
        total_entries=total_entries,
        error=error,
    )


@router.get("/audit/export/download")
async def audit_export_download(
    request: Request,
    format: str = "csv",
    start_date: str = "",
    end_date: str = "",
):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    if format not in ("csv", "json"):
        raise HTTPException(status_code=400, detail="format must be 'csv' or 'json'")

    try:
        entries = audit_log_service.read_recent_entries(limit=500)
        entries = audit_log_service.filter_by_date_range(entries, start_date or None, end_date or None)
    except AuditLogError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if format == "csv":
        content = entries_to_csv(entries)
        media_type = "text/csv"
        filename = f"audit-export-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    else:
        content = entries_to_json(entries)
        media_type = "application/json"
        filename = f"audit-export-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"

    try:
        audit(
            request,
            action="AUDIT_LOG_EXPORT",
            object=filename,
            result="SUCCESS",
            details={
                "format": format,
                "start_date": start_date or None,
                "end_date": end_date or None,
                "entry_count": len(entries),
            },
        )
    except Exception:
        logger.exception("Failed to write audit-export audit entry")

    return StreamingResponse(
        io.StringIO(content),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )