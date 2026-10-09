import logging

from fastapi import Request
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..services.system_status_service import SystemStatusService


logger = logging.getLogger(__name__)

router = APIRouter()


def get_current_user(request: Request) -> dict:
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", get_current_user(request))
    return templates.TemplateResponse(request, name, ctx)


@router.get("/monitoring", response_class=HTMLResponse)
async def monitoring_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    snapshot = SystemStatusService().get_snapshot()

    services = snapshot["services"]
    all_ok = all(s["ok"] for s in services)
    down_count = sum(1 for s in services if not s["ok"])

    return render(
        request,
        "monitoring.html",
        services=services,
        host=snapshot["host"],
        disks=snapshot["disks"],
        all_ok=all_ok,
        down_count=down_count,
    )