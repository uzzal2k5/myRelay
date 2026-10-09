import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from ..common import require_role
from ..config import settings
from ..services.postfix_service import PostfixService
from ..services.audit_service import audit


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/postfix",
    tags=["postfix"],
)
service = PostfixService(settings.postfix_policy_path, settings.postfix_backup_path)


def get_current_user(request: Request) -> dict:
    """
    Builds the current_user context object used by shared partials
    (topnav.html, sidebar.html).

    NOTE: assumes the session stores "username" and "role" keys set
    at login time. Keep this in sync with the same helper in
    certificates.py / smtp_policy/routes.py / ip_management/routes.py /
    relayhost/routes.py / recipient_domains/routes.py / policies/routes.py
    until this is centralized in one shared module.
    """
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", get_current_user(request))
    return templates.TemplateResponse(request, name, ctx)


@router.get("", response_class=HTMLResponse)
async def postfix(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    try:
        check = service.check()
    except Exception as exc:
        logger.exception("Failed to run postfix check")
        return render(request, "postfix.html", check="", error=str(exc))

    return render(request, "postfix.html", check=check.stdout + check.stderr)


@router.post("/check")
async def postfix_check(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    try:
        result = service.check()
    except Exception as exc:
        logger.exception("Failed to run postfix check")
        return render(request, "postfix.html", check="", error=str(exc))

    try:
        audit(
            request,
            "POSTFIX_CHECK",
            "postfix",
            result="SUCCESS" if result.returncode == 0 else "FAILED",
            error=result.stderr.strip() or None,
        )
    except Exception:
        logger.exception("Failed to write postfix check audit entry")

    return render(request, "postfix.html", check=result.stdout + result.stderr)


@router.post("/reload")
async def postfix_reload(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    try:
        result = service.reload()
    except Exception as exc:
        logger.exception("Failed to reload postfix")
        return render(request, "postfix.html", check="", error=str(exc))

    try:
        audit(
            request,
            "POSTFIX_RELOAD",
            "postfix",
            result="SUCCESS" if result.returncode == 0 else "FAILED",
            error=result.stderr.strip() or None,
        )
    except Exception:
        logger.exception("Failed to write postfix reload audit entry")

    return render(request, "postfix.html", check=result.stdout + result.stderr)