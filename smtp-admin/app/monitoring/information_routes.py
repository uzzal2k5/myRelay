import logging

from fastapi import Request, APIRouter
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..services.information import InformationService


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/server",
    tags=["Server"],
)


# ============================================================
# Current User
# ============================================================

def get_current_user(request: Request) -> dict:
    """
    Get the authenticated user from session.
    """
    return {
        "username": request.session.get("username"),
        "role": request.session.get(
            "role",
            "read_only",
        ),
    }


# ============================================================
# Template Renderer
# ============================================================

def render(
    request: Request,
    name: str,
    **ctx,
):
    """
    Render Jinja2 template.

    Important:
    The Request object must be passed as the first
    argument to this helper.
    """

    from ..main import templates

    ctx.setdefault(
        "current_user",
        get_current_user(request),
    )

    return templates.TemplateResponse(
        name,
        {
            "request": request,
            **ctx,
        },
    )


# ============================================================
# Server Information
# ============================================================

@router.get(
    "/information",
    response_class=HTMLResponse,
)
async def server_information(
    request: Request,
):
    """
    Display SMTP server information.
    """

    # --------------------------------------------------------
    # RBAC
    # --------------------------------------------------------

    guard = require_role(
        request,
        "security_admin",
        "smtp_admin",
        "read_only",
    )

    if guard:
        return guard

    # --------------------------------------------------------
    # Collect Information
    # --------------------------------------------------------

    try:
        information = (
            InformationService.get_information()
        )

    except Exception as exc:
        logger.exception(
            "Failed to collect server information"
        )

        information = {
            "system": {},
            "software": {},
            "services": {},
            "memory": {},
            "disks": {},
        }

    # --------------------------------------------------------
    # Render Template
    # --------------------------------------------------------

    return render(
        request,
        "information.html",
        system=information["system"],
        software=information["software"],
        services=information["services"],
        memory=information["memory"],
        disk=information["disk"],
    )