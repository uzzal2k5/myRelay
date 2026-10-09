import logging
from typing import List

from fastapi import (
    APIRouter,
    Request,
    Form,
    HTTPException,
)

from fastapi.responses import HTMLResponse

from ..common import require_role
from ..services.recipient_domain_service import RecipientDomainService


logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/recipient/domains",
    tags=["Recipient Domains"],
)


def get_service():
    return RecipientDomainService()


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
async def recipient_domains(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")

    if guard:
        return guard

    service = get_service()

    try:
        policies = service.get_all_policies()

    except Exception as exc:
        logger.exception("Failed to load recipient domain policies")
        raise HTTPException(status_code=500, detail=str(exc))

    return render(
        request,
        "recipient_domains.html",
        policies=policies,
    )


@router.post("/{policy}", response_class=HTMLResponse)
async def update_recipient_policy(
    request: Request,
    policy: str,
    values: List[str] = Form(default=[]),
    actions: List[str] = Form(default=[]),
    messages: List[str] = Form(default=[]),
):
    guard = require_role(request, "security_admin", "smtp_admin")

    if guard:
        return guard

    service = get_service()

    try:
        service.validate_policy(policy)

        entries = []

        for index, value in enumerate(values):
            value = value.strip()

            if not value:
                continue

            action = (
                actions[index]
                if index < len(actions)
                else ("OK" if policy == "allowed" else "REJECT")
            )

            message = messages[index] if index < len(messages) else ""

            entries.append({
                "value": value,
                "action": action,
                "message": message,
            })

        result = service.apply_policy(policy, entries)

        policies = service.get_all_policies()

        backup = result.get("backup")

        success_message = f"{policies[policy]['title']} updated successfully."

        if backup:
            success_message += f" Backup created: {backup}"

        return render(
            request,
            "recipient_domains.html",
            policies=policies,
            success=success_message,
        )

    except ValueError as exc:
        logger.warning(
            "Recipient domain policy validation failed for '%s': %s",
            policy,
            exc,
        )

        policies = service.get_all_policies()

        return render(
            request,
            "recipient_domains.html",
            policies=policies,
            error=str(exc),
        )

    except Exception as exc:
        logger.exception("Failed to update recipient domain policy: %s", policy)
        raise HTTPException(status_code=500, detail=str(exc))