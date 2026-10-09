import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..config import settings
from ..services.redis_status_service import RedisStatusService, RedisStatusError


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/redis",
    tags=["Redis"],
)


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


def get_service() -> RedisStatusService:
    """
    NOTE: attribute names guessed defensively via getattr + fallback,
    same caveat as redis_config_service.py / redis_data_route.py -
    confirm against config.py, and point this at a shared Redis
    client/connection factory instead if one already exists.
    """
    host = getattr(settings, "redis_host", "127.0.0.1")
    port = getattr(settings, "redis_port", 6379)
    db = getattr(settings, "redis_db", 0)
    password = getattr(settings, "redis_password", None)

    return RedisStatusService(host=host, port=port, db=db, password=password)


@router.get("/status", response_class=HTMLResponse)
async def redis_status_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    service = get_service()
    redis_ok = service.ping()

    status = None
    error = None

    if redis_ok:
        try:
            status = service.get_status()
        except RedisStatusError as exc:
            logger.warning("Failed to fetch Redis status details: %s", exc)
            error = str(exc)
    else:
        error = "Unable to connect to Redis."

    return render(
        request,
        "redis_status.html",
        redis_ok=redis_ok,
        status=status,
        error=error,
    )