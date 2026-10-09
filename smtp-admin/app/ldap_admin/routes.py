import logging

from fastapi import APIRouter, Form, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from ..services.ldap_config_service import LdapConfigService

from ..common import require_role
from ..config import settings




logger = logging.getLogger(__name__)

router = APIRouter()


def get_current_user(request: Request) -> dict:
    """Same helper as every other router; feeds topnav.html / sidebar.html."""
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", get_current_user(request))
    return templates.TemplateResponse(request, name, ctx)


def get_service() -> LdapConfigService:
    return LdapConfigService(load_ldap_settings(settings))


def _is_editor(request: Request) -> bool:
    return request.session.get("role") in ("security_admin", "smtp_admin")


def _render_page(request: Request, service: LdapConfigService, **extra):
    context = {
        "cfg": service.cfg.describe(),
        "is_editor": _is_editor(request),
        "connection_result": None,
        "lookup_result": None,
        "lookup_error": None,
        "lookup_username": "",
    }
    context.update(extra)
    return render(request, "ldap.html", **context)


@router.get("/ldap", response_class=HTMLResponse)
async def ldap_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    return _render_page(request, get_service())


@router.post("/ldap/test-connection", response_class=HTMLResponse)
async def ldap_test_connection(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()
    # ldap3 is blocking; run it off the event loop so a slow directory
    # server cannot stall every other request.
    result = await run_in_threadpool(service.test_connection)

    failed_steps = [s["detail"] for s in result["steps"] if not s["ok"]]
    try:
        audit(
            request,
            "LDAP_CONNECTION_TEST",
            "ldap",
            result="SUCCESS" if result["ok"] else "FAILED",
            error=failed_steps[0] if failed_steps else None,
        )
    except Exception:
        logger.exception("Failed to write LDAP connection test audit entry")

    return _render_page(request, service, connection_result=result)


@router.post("/ldap/lookup", response_class=HTMLResponse)
async def ldap_lookup(request: Request, username: str = Form(...)):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()
    lookup_result = None
    lookup_error = None

    try:
        lookup_result = await run_in_threadpool(service.lookup_user, username)
    except (ValueError, LdapConfigError) as exc:
        lookup_error = str(exc)
    except Exception:
        logger.exception("Unexpected error during LDAP user lookup")
        lookup_error = "The lookup failed unexpectedly. See the application log for details."

    try:
        audit(
            request,
            "LDAP_USER_LOOKUP",
            username[:64],
            result="FAILED" if lookup_error else "SUCCESS",
            error=lookup_error,
        )
    except Exception:
        logger.exception("Failed to write LDAP user lookup audit entry")

    return _render_page(
        request,
        service,
        lookup_result=lookup_result,
        lookup_error=lookup_error,
        lookup_username=username[:64],
    )