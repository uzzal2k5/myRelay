import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..common import require_role


logger = logging.getLogger(__name__)

router = APIRouter()


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


@router.get("/pipaops", response_class=HTMLResponse)
async def about_pipaops(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    return render(
        request,
        "about.html",
        whatsapp_number="+8801715519132",
        whatsapp_link="https://wa.me/8801715519132",
        contact_email="uzzal2k5@gmail.com",
    )