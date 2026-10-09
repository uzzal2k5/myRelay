import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..config import settings
from ..services.audit_service import audit
from ..services.redis_config_service import RedisConfigService, RedisConfigError


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/redis",
    tags=["Redis"],
)


def get_current_user(request: Request) -> dict:
    """
    Builds the current_user context object used by shared partials
    (topnav.html, sidebar.html). Kept in sync with the same helper
    duplicated across certificates.py / smtp_policy / ip_management /
    relayhost / recipient_domains / policies / postfix / audit routers.
    """
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", get_current_user(request))
    return templates.TemplateResponse(request, name, ctx)


def get_service() -> RedisConfigService:
    """
    Builds the Redis config service from settings, defensively: every
    attribute uses getattr + a fallback rather than settings.<name>
    directly, so a missing/renamed settings field degrades to a
    default instead of crashing the app at import time (see this
    project's history with AttributeError on Settings for precedent).

    NOTE: if the app already has a shared Redis client/connection
    factory (e.g. one SmtpPolicyService or the existing /redis policy
    page already uses), this should be pointed at that instead of
    opening an independent second connection.
    """
    host = getattr(settings, "redis_host", "127.0.0.1")
    port = getattr(settings, "redis_port", 6379)
    db = getattr(settings, "redis_db", 0)
    password = getattr(settings, "redis_password", None)

    return RedisConfigService(host=host, port=port, db=db, password=password)


def _gather_page_context(service: RedisConfigService):
    """Shared data-fetch used by both the GET page and the POST save
    handler, so a config update redraws the same full picture."""
    connection_info = service.connection_info()
    redis_ok = service.ping()

    server_info = {}
    editable_config = {}
    all_config = {}
    fetch_error = None

    try:
        server_info = service.server_summary()
    except RedisConfigError as exc:
        logger.warning("Could not fetch Redis server summary: %s", exc)
        fetch_error = str(exc)

    try:
        editable_config = service.get_editable_config()
    except Exception:
        logger.exception("Could not fetch editable Redis config")

    try:
        all_config = service.get_all_config()
    except RedisConfigError as exc:
        logger.warning("Could not fetch full Redis config: %s", exc)
        if not fetch_error:
            fetch_error = str(exc)

    return connection_info, redis_ok, server_info, editable_config, all_config, fetch_error


@router.get("/config", response_class=HTMLResponse)
async def redis_config_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    is_editor = request.session.get("role") in ("security_admin", "smtp_admin")

    service = get_service()
    connection_info, redis_ok, server_info, editable_config, all_config, error = (
        _gather_page_context(service)
    )

    return render(
        request,
        "redis_config.html",
        connection_info=connection_info,
        redis_ok=redis_ok,
        server_info=server_info,
        editable_config=editable_config,
        all_config=all_config,
        is_editor=is_editor,
        error=error,
        success=None,
    )


@router.post("/config/save")
async def redis_config_save(request: Request, key: str = Form(...), value: str = Form(...)):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()
    error = None
    success = None

    try:
        result = service.set_config(key, value)

        success = (
            f"Updated '{result['key']}' from '{result['old_value']}' to "
            f"'{result['new_value']}'. This change is live immediately but "
            f"is not persisted to redis.conf until a CONFIG REWRITE or a "
            f"manual config file update - it will revert on Redis restart "
            f"otherwise."
        )

        try:
            audit(
                request,
                action="REDIS_CONFIG_UPDATE",
                details={
                    "key": result["key"],
                    "old_value": result["old_value"],
                    "new_value": result["new_value"],
                },
            )
        except Exception:
            logger.exception("Failed to write Redis config audit entry")

    except RedisConfigError as exc:
        logger.warning("Redis config update rejected: %s", exc)
        error = str(exc)
    except Exception as exc:
        logger.exception("Unexpected error updating Redis config key %s", key)
        error = str(exc)

    is_editor = request.session.get("role") in ("security_admin", "smtp_admin")
    connection_info, redis_ok, server_info, editable_config, all_config, fetch_error = (
        _gather_page_context(service)
    )

    return render(
        request,
        "redis_config.html",
        connection_info=connection_info,
        redis_ok=redis_ok,
        server_info=server_info,
        editable_config=editable_config,
        all_config=all_config,
        is_editor=is_editor,
        error=error or fetch_error,
        success=success,
    )