import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..config import settings
from ..services.ldap_config_service import LdapConfigError, LdapConfigService, load_ldap_settings


logger = logging.getLogger(__name__)

router = APIRouter()


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    })
    return templates.TemplateResponse(request, name, ctx)


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    session_username = request.session.get("username") or ""
    session_role = request.session.get("role", "read_only")

    directory_info = None
    directory_error = None

    try:
        service = LdapConfigService(load_ldap_settings(settings))
        directory_info = service.lookup_user(session_username)
    except (ValueError, LdapConfigError) as exc:
        directory_error = str(exc)
    except Exception:
        logger.exception("Unexpected error looking up own profile in AD for %s", session_username)
        directory_error = "The directory lookup failed unexpectedly. See the application log for details."

    return render(
        request,
        "profile.html",
        session_username=session_username,
        session_role=session_role,
        directory_info=directory_info,
        directory_error=directory_error,
    )