import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..config import settings
from ..services.audit_log_service import AuditLogError, audit_log_service


logger = logging.getLogger(__name__)

router = APIRouter()


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    })
    return templates.TemplateResponse(request, name, ctx)


def _session_duration_text(login_time_iso: str) -> str:
    try:
        started = datetime.fromisoformat(login_time_iso)
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - started

        minutes = int(delta.total_seconds() // 60)
        if minutes < 1:
            return "less than a minute ago"
        if minutes < 60:
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"

        hours = minutes // 60
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    except Exception:
        return "unknown"


@router.get("/account/security", response_class=HTMLResponse)
async def account_security_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    username = request.session.get("username") or ""
    role = request.session.get("role", "read_only")
    login_time_iso = request.session.get("login_time")

    error = None
    own_events = []

    try:
        all_entries = audit_log_service.read_recent(limit=500)
        own_events = [
            e for e in all_entries
            if not e.get("_parse_error")
            and (e.get("username") or "").lower() == username.lower()
            and (e.get("action") or "").upper() in ("LOGIN", "LOGOUT")
        ][:20]
    except AuditLogError as exc:
        error = str(exc)

    connection_secure = bool(settings.ad_use_ldaps or settings.ad_use_starttls)
    connection_transport = (
        "LDAPS" if settings.ad_use_ldaps else "StartTLS" if settings.ad_use_starttls else "Plain LDAP"
    )

    return render(
        request,
        "account_security.html",
        username=username,
        role=role,
        login_time_iso=login_time_iso,
        session_duration=_session_duration_text(login_time_iso) if login_time_iso else "unknown",
        session_timeout_minutes=settings.session_timeout_minutes,
        connection_secure=connection_secure,
        connection_transport=connection_transport,
        cert_verified=settings.ad_verify_cert,
        own_events=own_events,
        error=error,
    )