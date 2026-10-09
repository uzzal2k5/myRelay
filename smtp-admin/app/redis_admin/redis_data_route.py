import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..common import require_role
from ..config import settings
from ..services.audit_service import audit
from ..services.redis_data_service import RedisDataService, RedisDataError


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


def get_service() -> RedisDataService:
    """
    NOTE: attribute names guessed defensively via getattr + fallback,
    same caveat as redis_config_service.py - confirm against config.py,
    and point this at a shared Redis client/connection factory instead
    if one already exists elsewhere in the app.
    """
    host = getattr(settings, "redis_host", "127.0.0.1")
    port = getattr(settings, "redis_port", 6379)
    db = getattr(settings, "redis_db", 0)
    password = getattr(settings, "redis_password", None)

    return RedisDataService(host=host, port=port, db=db, password=password)


@router.get("/data", response_class=HTMLResponse)
async def redis_data_browser(request: Request, pattern: str = "*", cursor: int = 0):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    is_editor = request.session.get("role") in ("security_admin", "smtp_admin")

    service = get_service()
    error = None
    next_cursor = 0
    entries = []

    try:
        next_cursor, entries = service.scan_keys(cursor=cursor, pattern=pattern)
    except RedisDataError as exc:
        logger.warning("Redis data scan failed: %s", exc)
        error = str(exc)

    return render(
        request,
        "redis_data.html",
        pattern=pattern,
        entries=entries,
        cursor=cursor,
        next_cursor=next_cursor,
        has_more=next_cursor != 0,
        is_editor=is_editor,
        error=error,
    )


@router.get("/data/key", response_class=HTMLResponse)
async def redis_data_key_detail(request: Request, key: str, pattern: str = "*", cursor: int = 0):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    is_editor = request.session.get("role") in ("security_admin", "smtp_admin")

    service = get_service()
    error = None
    detail = None

    try:
        detail = service.get_key_detail(key)
    except RedisDataError as exc:
        logger.warning("Redis data detail lookup failed for key %s: %s", key, exc)
        error = str(exc)

    return render(
        request,
        "redis_data_detail.html",
        key=key,
        detail=detail,
        pattern=pattern,
        cursor=cursor,
        is_editor=is_editor,
        error=error,
    )


@router.post("/data/key/delete")
async def redis_data_key_delete(
    request: Request,
    key: str = Form(...),
    pattern: str = Form("*"),
    cursor: int = Form(0),
):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        deleted = service.delete_key(key)

        try:
            audit(
                request,
                action="REDIS_KEY_DELETE",
                details={"key": key, "deleted": deleted},
            )
        except Exception:
            logger.exception("Failed to write Redis key deletion audit entry")

    except RedisDataError as exc:
        logger.warning("Redis key deletion rejected for %s: %s", key, exc)

    return RedirectResponse(
        url=f"/redis/data?pattern={pattern}&cursor={cursor}",
        status_code=303,
    )