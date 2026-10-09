import logging
from typing import Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..config import settings
from ..services.relayhost_service import RelayhostService


logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/relay/endpoint",
    tags=["Relay Endpoint"],
)


service = RelayhostService(
    main_cf_path="/etc/postfix/main.cf",
    backup_path="/etc/postfix/backup",
)



def get_current_user(request: Request) -> dict:
    """
    Builds the current_user context object used by shared partials
    (topnav.html, sidebar.html).

    NOTE: assumes the session stores "username" and "role" keys set
    at login time. Keep this in sync with the same helper in
    certificates.py / smtp_policy/routes.py / ip_management/routes.py
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


# ---------------------------------------------------------
# View
# ---------------------------------------------------------

@router.get("", response_class=HTMLResponse)
async def relayhost_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")

    if guard:
        return guard

    error = None
    success = None

    try:
        relayhost = service.get_relayhost()

    except Exception as exc:
        logger.exception("Failed to load relayhost configuration")

        relayhost = {
            "configured": False,
            "raw": "",
            "endpoint": "",
            "port": "",
        }

        error = str(exc)

    return render(
        request,
        "relayhost.html",
        relayhost=relayhost,
        error=error,
        success=success,
    )


# ---------------------------------------------------------
# Update
# ---------------------------------------------------------

@router.post("/update", response_class=HTMLResponse)
async def update_relayhost(
    request: Request,
    endpoint: str = Form(...),
    port: int = Form(...),
):
    guard = require_role(request, "security_admin", "smtp_admin")

    if guard:
        return guard

    error = None
    success = None

    try:
        result = service.update_relayhost(
            endpoint=endpoint,
            port=port,
        )

        success = result["message"]

        relayhost = service.get_relayhost()

    except Exception as exc:
        logger.exception("Failed to update relayhost")

        error = str(exc)

        try:
            relayhost = service.get_relayhost()
        except Exception:
            relayhost = {
                "configured": False,
                "raw": "",
                "endpoint": endpoint,
                "port": port,
            }

    return render(
        request,
        "relayhost.html",
        relayhost=relayhost,
        error=error,
        success=success,
    )