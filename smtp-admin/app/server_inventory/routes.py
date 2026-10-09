import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..common import require_role
from ..services.audit_log_service import audit
from ..services.server_inventory_service import ServerInventoryError, ServerInventoryService, VALID_ENVIRONMENTS, VALID_ROLES


logger = logging.getLogger(__name__)

router = APIRouter()


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    })
    return templates.TemplateResponse(request, name, ctx)


def get_service() -> ServerInventoryService:
    return ServerInventoryService()


def _is_editor(request: Request) -> bool:
    return request.session.get("role") in ("security_admin", "smtp_admin")


@router.get("/server/inventory", response_class=HTMLResponse)
async def server_inventory_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    service = get_service()
    error = None
    servers = []

    try:
        servers = service.list_servers()
    except ServerInventoryError as exc:
        error = str(exc)

    return render(
        request,
        "server_inventory.html",
        servers=servers,
        is_editor=_is_editor(request),
        environments=sorted(VALID_ENVIRONMENTS),
        roles=sorted(VALID_ROLES),
        error=error,
        success=None,
    )


@router.post("/server/inventory/add", response_class=HTMLResponse)
async def server_inventory_add(
    request: Request,
    name: str = Form(...),
    hostname: str = Form(...),
    environment: str = Form(...),
    role: str = Form(...),
    port: int = Form(25),
    notes: str = Form(""),
):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()
    error = None
    success = None

    try:
        record = service.add_server(name, hostname, environment, role, port, notes)
        success = f"Added server '{record['name']}'."

        try:
            audit(request, "SERVER_INVENTORY_ADD", record["name"], result="SUCCESS",
                  new_value={"hostname": hostname, "environment": environment, "role": role})
        except Exception:
            logger.exception("Failed to write server inventory add audit entry")

    except (ValueError, ServerInventoryError) as exc:
        error = str(exc)

    servers = []
    try:
        servers = service.list_servers()
    except ServerInventoryError as exc:
        error = error or str(exc)

    return render(
        request, "server_inventory.html", servers=servers, is_editor=True,
        environments=sorted(VALID_ENVIRONMENTS), roles=sorted(VALID_ROLES),
        error=error, success=success,
    )


@router.post("/server/inventory/{server_id}/delete")
async def server_inventory_delete(request: Request, server_id: str):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        server = service.get_server(server_id)
        deleted = service.delete_server(server_id)

        try:
            audit(request, "SERVER_INVENTORY_DELETE", server["name"] if server else server_id,
                  result="SUCCESS" if deleted else "FAILED")
        except Exception:
            logger.exception("Failed to write server inventory delete audit entry")

    except ServerInventoryError:
        logger.exception("Failed to delete server %s from inventory", server_id)

    return RedirectResponse(url="/server/inventory", status_code=303)


@router.post("/server/inventory/{server_id}/check")
async def server_inventory_check(request: Request, server_id: str):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    service = get_service()
    server = service.get_server(server_id)

    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)

    result = service.check_reachability(server["hostname"], server.get("port", 25))
    return JSONResponse(result)