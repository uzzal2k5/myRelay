from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from ..common import require_role
from ..config import settings
from ..services.postfix_service import PostfixService
from ..services.audit_service import audit
import logging
from starlette import status
from typing import Optional
from ..services.certificate_service import CertificateService, CertificateError


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/certificates",
    tags=["Certificates"],
)
certificate_service = CertificateService(settings.postfix_backup_path)


def get_current_user(request: Request) -> dict:
    """
    Builds the current_user context object used by shared partials
    (topnav.html, sidebar.html). Centralizing this here means every
    route that calls render() gets it automatically instead of each
    route having to remember to build it.

    NOTE: this assumes the session stores "username" and "role" keys
    set at login time (e.g. after AD-group -> role mapping in
    require_role / your auth flow). Adjust the keys below if
    common.py stores this differently.
    """
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }


def render(request: Request, name: str, **ctx):
    """
    Single entry point for rendering templates in this router.
    Guarantees current_user is always present in context so shared
    partials never crash with UndefinedError, no matter which route
    calls this.
    """
    ctx.setdefault("current_user", get_current_user(request))
    ctx.setdefault("request", request)
    return request.app.state.templates.TemplateResponse(request, name, ctx)


@router.get("", response_class=HTMLResponse)
async def certificate_page(request: Request, filename: Optional[str] = None):
    # Everyone listed here can view certificates.
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    files = []
    selected = None
    certificate_text = ""
    details = None
    error = None

    try:
        files = certificate_service.list_certificates()
        selected = filename if filename in files else (files[0] if files else None)

        if selected:
            certificate_text = certificate_service.read_certificate(selected)
            details = certificate_service.get_certificate_details(selected)

    except CertificateError as exc:
        logger.warning("Certificate page error: %s", exc)
        files = []
        selected = None
        certificate_text = ""
        details = None
        error = str(exc)

    return render(
        request,
        "certificates.html",
        certificates=files,
        selected_certificate=selected,
        certificate_text=certificate_text,
        certificate_details=details,
        error=error,
    )


@router.post("/save")
async def save_certificate(request: Request):
    # Only admins can edit certificate files.
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    form = await request.form()
    filename = str(form.get("filename", "")).strip()
    content = str(form.get("certificate_text", ""))

    # Adapt this to your application's session/user identity.
    user = request.session.get("username", "unknown")

    try:
        certificate_service.save_certificate(
            filename=filename,
            content=content,
            actor=user,
        )
        return RedirectResponse(
            url=f"/certificates?filename={filename}&saved=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    except CertificateError as exc:
        logger.warning("Certificate update rejected for %s: %s", filename, exc)
        return RedirectResponse(
            url=f"/certificates?filename={filename}&error=validation",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    except Exception:
        logger.exception("Certificate update failed for %s", filename)
        return RedirectResponse(
            url=f"/certificates?filename={filename}&error=save",
            status_code=status.HTTP_303_SEE_OTHER,
        )