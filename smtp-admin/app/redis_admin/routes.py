from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from ..common import require_role
from ..services.redis_service import RedisService
from ..services.audit_service import audit

router = APIRouter(
    prefix="/redis",
    tags=["Redis"],
)
redis_service = RedisService()

def get_service():
    return PostfixService(settings.postfix_backup_path)


def get_current_user(request: Request) -> dict:
    """
    Builds the current_user context object used by shared partials
    (topnav.html, sidebar.html).

    NOTE: assumes the session stores "username" and "role" keys set
    at login time. Keep this in sync with the same helper in
    certificates.py / smtp_policy/routes.py / ip_management/routes.py /
    relayhost/routes.py until this is centralized in one shared module.
    """
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }

def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", get_current_user(request))
    return templates.TemplateResponse(request, name, ctx)

@router.get("", response_class=HTMLResponse)
async def redis_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard: return guard
    keys = redis_service.policy_keys() if redis_service.ping() else []
    return render(request, "redis.html", keys=keys, error=None)

@router.post("/policy")
async def redis_policy(
    request: Request,
    username: str = Form(...),
    minute: int = Form(10),
    hour: int = Form(100),
    day: int = Form(500),
    week: int = Form(3500),
    month: int = Form(15000),
    year: int = Form(100000),
):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard: return guard

    values = {"minute": minute, "hour": hour, "day": day, "week": week,
              "month": month, "year": year, "status": "enabled"}
    if any(v < 0 for v in values.values() if isinstance(v, int)):
        return RedirectResponse("/redis", status_code=303)

    key = f"smtp:policy:user:{username.strip().lower()}"
    try:
        old = redis_service.get_policy(key)
        redis_service.set_policy(key, values)
        audit(request, "UPDATE_REDIS_POLICY", key, old_value=old, new_value=values)
    except Exception as exc:
        audit(request, "UPDATE_REDIS_POLICY", key, result="FAILED", error=str(exc))
    return RedirectResponse("/redis", status_code=303)
