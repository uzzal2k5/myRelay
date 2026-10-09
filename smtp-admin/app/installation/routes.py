import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..services.installation_check_service import InstallationCheckService


logger = logging.getLogger(__name__)

router = APIRouter()


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    })
    return templates.TemplateResponse(request, name, ctx)


@router.get("/installation", response_class=HTMLResponse)
async def installation_page(request: Request):
    # Matches the sidebar's existing is_admin gating for this link
    # (smtp_admin only) - this reveals privileged-account/sudoers
    # details that shouldn't be visible to security_admin or read_only.
    guard = require_role(request, "smtp_admin")
    if guard:
        return guard

    report = InstallationCheckService().get_report()

    return render(request, "installation.html", report=report)