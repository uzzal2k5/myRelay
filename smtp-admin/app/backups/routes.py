import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..common import require_role
from ..services.audit_log_service import audit
from ..services.backup_service import BackupService, BackupServiceError



logger = logging.getLogger(__name__)

router = APIRouter()


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    })
    return templates.TemplateResponse(request, name, ctx)


def get_service() -> BackupService:
    return BackupService()


def _is_editor(request: Request) -> bool:
    return request.session.get("role") in ("security_admin", "smtp_admin")


@router.get("/backups", response_class=HTMLResponse)
async def backups_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    service = get_service()
    error = None
    success = None
    backups = []
    total_size = 0

    try:
        backups = service.list_backups()
        total_size = service.total_size_bytes(backups)
    except Exception as exc:
        logger.exception("Failed to list backups")
        error = str(exc)

    return render(
        request, "backups.html", backups=backups, total_size=total_size,
        is_editor=_is_editor(request), error=error, success=success,
    )


@router.get("/backups/{filename}/preview", response_class=HTMLResponse)
async def backups_preview(request: Request, filename: str):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()
    error = None
    preview = None

    try:
        preview = service.preview_restore(filename)
    except (ValueError, BackupServiceError) as exc:
        error = str(exc)
    except Exception:
        logger.exception("Unexpected error building restore preview for %s", filename)
        error = "Could not build a preview for this backup. See the application log for details."

    return render(request, "backup_restore_preview.html", preview=preview, filename=filename, error=error)


@router.post("/backups/restore", response_class=HTMLResponse)
async def backups_restore(request: Request, filename: str = Form(...)):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()
    error = None
    success = None

    try:
        result = service.restore_backup(filename)
        success = (
            f"Restored '{result['name']}' from backup. "
            f"A backup of the previous content was created at {result['backup']}."
        )

        try:
            audit(request, "BACKUP_RESTORE", result["name"], result="SUCCESS",
                  old_value=None, new_value=filename)
        except Exception:
            logger.exception("Failed to write backup restore audit entry")

    except (ValueError, BackupServiceError, RuntimeError, FileNotFoundError) as exc:
        logger.warning("Backup restore failed for %s: %s", filename, exc)
        error = str(exc)

        try:
            audit(request, "BACKUP_RESTORE", filename, result="FAILED", error=str(exc))
        except Exception:
            logger.exception("Failed to write backup restore failure audit entry")

    backups = []
    total_size = 0
    try:
        backups = service.list_backups()
        total_size = service.total_size_bytes(backups)
    except Exception as exc:
        error = error or str(exc)

    return render(
        request, "backups.html", backups=backups, total_size=total_size,
        is_editor=True, error=error, success=success,
    )


@router.post("/backups/{filename}/delete")
async def backups_delete(request: Request, filename: str):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        service.delete_backup(filename)
        try:
            audit(request, "BACKUP_DELETE", filename, result="SUCCESS")
        except Exception:
            logger.exception("Failed to write backup delete audit entry")
    except (ValueError, BackupServiceError) as exc:
        logger.warning("Backup delete failed for %s: %s", filename, exc)
        try:
            audit(request, "BACKUP_DELETE", filename, result="FAILED", error=str(exc))
        except Exception:
            logger.exception("Failed to write backup delete failure audit entry")

    return RedirectResponse(url="/backups", status_code=303)