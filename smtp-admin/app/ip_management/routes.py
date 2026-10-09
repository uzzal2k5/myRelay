import logging
from typing import List

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..config import settings
from ..services.audit_service import audit
from ..services.ip_management_service import IPManagementService


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/ip/mgmt",
    tags=["IP Management"],
)

service = IPManagementService(backup_path=settings.postfix_backup_path)


def get_current_user(request: Request) -> dict:
    """
    Builds the current_user context object used by shared partials
    (topnav.html, sidebar.html).

    NOTE: assumes the session stores "username" and "role" keys set
    at login time. Keep this in sync with the same helper in
    certificates.py / smtp_policy/routes.py until this is
    centralized in one shared module.
    """
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }


def render(request, name, **ctx):
    from ..main import templates

    ctx.setdefault("current_user", get_current_user(request))
    return templates.TemplateResponse(request, name, ctx)


# =========================================================
# Display
# =========================================================

@router.get("", response_class=HTMLResponse)
async def ip_management_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")

    if guard:
        return guard

    error = None

    try:
        policies = service.get_all_policies()

    except Exception as exc:
        logger.exception("Failed to load IP management configuration")

        policies = {
            "allowed": [],
            "denied": [],
            "blocked": [],
        }

        error = str(exc)

    return render(
        request,
        "ip_management.html",
        policies=policies,
        error=error,
        success=None,
    )


# =========================================================
# Apply
# =========================================================

@router.post("/{policy}", response_class=HTMLResponse)
async def apply_ip_policy(
    request: Request,
    policy: str,
    addresses: List[str] = Form(default=[]),
):
    guard = require_role(request, "security_admin", "smtp_admin")

    if guard:
        return guard

    error = None
    success = None

    try:
        if policy not in ("allowed", "denied", "blocked"):
            raise ValueError(f"Invalid IP policy: {policy}")

        result = service.apply_policy(
            policy=policy,
            addresses=addresses,
        )

        success = result["message"]

        # -----------------------------------------------------
        # Audit
        # -----------------------------------------------------

        try:
            audit(
                request,
                action=f"IP_POLICY_UPDATE_{policy.upper()}",
                details={
                    "file": result["file"],
                    "added": result["added"],
                    "removed": result["removed"],
                    "backup": result.get("backup"),
                },
            )
        except Exception:
            logger.exception("Failed to write IP policy audit entry")

    except Exception as exc:
        logger.exception("Failed to apply IP policy: %s", policy)

        error = str(exc)

    try:
        policies = service.get_all_policies()

    except Exception as exc:
        logger.exception("Failed to reload IP policy configuration")

        policies = {
            "allowed": [],
            "denied": [],
            "blocked": [],
        }

        if not error:
            error = str(exc)

    return render(
        request,
        "ip_management.html",
        policies=policies,
        error=error,
        success=success,
    )