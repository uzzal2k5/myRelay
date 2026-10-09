import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..common import require_role
from ..services.audit_log_service import audit
from ..services.postfix_systemd_service import PostfixSystemdError, PostfixSystemdService


logger = logging.getLogger(__name__)

router = APIRouter()


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    })
    return templates.TemplateResponse(request, name, ctx)


def get_service() -> PostfixSystemdService:
    return PostfixSystemdService()


@router.get("/postfix/control", response_class=HTMLResponse)
async def postfix_control_page(request: Request):
    # Matches the sidebar's is_admin gating for this link.
    guard = require_role(request, "smtp_admin")
    if guard:
        return guard

    service = get_service()
    error = None
    status = {"active": "unknown", "enabled": "unknown"}

    try:
        status = service.get_status()
    except PostfixSystemdError as exc:
        error = str(exc)

    return render(request, "postfix_control.html", status=status, error=error)


@router.post("/postfix/control/{action}")
async def postfix_control_action(request: Request, action: str):
    guard = require_role(request, "smtp_admin")
    if guard:
        return guard

    valid_actions = {"start", "stop", "restart", "enable", "disable"}
    if action not in valid_actions:
        return RedirectResponse(url="/postfix/control?error=invalid_action", status_code=303)

    service = get_service()

    try:
        service.__getattribute__(action)()

        try:
            audit(request, f"POSTFIX_{action.upper()}", "postfix.service", result="SUCCESS")
        except Exception:
            logger.exception("Failed to write Postfix %s audit entry", action)

    except PostfixSystemdError as exc:
        logger.warning("Postfix %s failed: %s", action, exc)

        try:
            audit(request, f"POSTFIX_{action.upper()}", "postfix.service", result="FAILED", error=str(exc))
        except Exception:
            logger.exception("Failed to write Postfix %s failure audit entry", action)

        return RedirectResponse(url=f"/postfix/control?error={action}_failed", status_code=303)

    return RedirectResponse(url="/postfix/control", status_code=303)