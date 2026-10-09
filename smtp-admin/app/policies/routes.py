from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from ..common import require_role
from ..config import settings
from ..services.postfix_service import PostfixService
import logging
from ..services.audit_service import audit

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/postfix",
    tags=["Postfix Policy"],
)

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

@router.get("/policies", response_class=HTMLResponse)
async def policies(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard: return guard
    service = get_service()
    maps = service.discover_existing_maps()
    return render(request, "policies.html", maps=maps, error=None)

@router.get("/policies/map", response_class=HTMLResponse)
async def map_view(request: Request, path: str):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard: return guard
    service = get_service()
    maps = service.discover_existing_maps()
    if path not in maps:
        return RedirectResponse("/forbidden", status_code=303)
    lines = service.read_map(path)
    return render(request, "map_edit.html", path=path, lines="\n".join(lines), readonly=request.session.get("role") == "read_only")

@router.post("/policies/map")
async def map_save(request: Request, path: str = Form(...), content: str = Form(...)):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard: return guard
    service = get_service()
    maps = service.discover_existing_maps()
    if path not in maps:
        return RedirectResponse("/forbidden", status_code=303)

    old = service.read_map(path)
    try:
        result = service.write_existing_map(path, content.splitlines())
        audit(request, "UPDATE_EXISTING_POSTFIX_MAP", path,
              old_value=old, new_value=content.splitlines())
    except Exception as exc:
        audit(request, "UPDATE_EXISTING_POSTFIX_MAP", path, result="FAILED", error=str(exc))
        return render(request, "map_edit.html", path=path, lines=content,
                      readonly=False, error=str(exc))
    return RedirectResponse(f"/policies/map?path={path}", status_code=303)

@router.get("/config", response_class=HTMLResponse)
async def effective_config(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard: return guard
    service = get_service()
    try:
        config = service.show_effective_config()
        return render(request, "config.html", config=config)
    except Exception as exc:
        return render(request, "config.html", config="", error=str(exc))


@router.get("/submission/config", response_class=HTMLResponse)
async def submission_config(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard: return guard
    logger.info("GET /submission/config")
    service = get_service()
    try:
        config = service.get_submission_restrictions()
        return render(request, "config.html", config=config)
    except Exception as exc:
        return render(request, "config.html", config="", error=str(exc))


@router.get("/submission/view", response_class=HTMLResponse)
async def view_submission_config(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard: return guard
    logger.info("GET /submission/view")
    service = get_service()
    try:
        config = service.view_submission_restrictions()
        return render(request, "config.html", config=config)

    except Exception as exc:
            return render(request, "config.html", config="", error=str(exc))


@router.get("/submission/format", response_class=HTMLResponse)
async def view_submission_config(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard: return guard
    logger.info("GET /submission/format")
    #formatted_config = format_submission_restrictions(config)
    service = get_service()
    try:
        config = service.format_submission_restrictions()
        #return render(request, "submission-config.html", config=config)
        return templates.TemplateResponse(
                "config.html",
                {
                    "request": request,
                    "submission_config": submission_config,
                },
            )
    except Exception as exc:
            return render(request, "submission-config.html", config="", error=str(exc))