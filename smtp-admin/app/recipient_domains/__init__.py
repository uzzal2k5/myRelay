from typing import List

from fastapi import (
    APIRouter,
    Request,
    Form,
    HTTPException,
)
from fastapi.responses import HTMLResponse

from ..services.recipient_domain_service import (
    RecipientDomainService,
)
from ..common import require_role


router = APIRouter(
    prefix="/recipient-domains",
    tags=["Recipient Domains"],
)


def get_service():

    return RecipientDomainService()


def render(
    request,
    name,
    **ctx,
):

    from ..main import templates

    return templates.TemplateResponse(
        request,
        name,
        ctx,
    )


# ============================================================
# View
# ============================================================

@router.get(
    "",
    response_class=HTMLResponse,
)
async def recipient_domains(
    request: Request,
):

    guard = require_role(
        request,
        "security_admin",
        "smtp_admin",
        "read_only",
    )

    if guard:
        return guard

    service = get_service()

    policies = service.get_all_policies()

    return render(
        request,
        "recipient_domains.html",
        policies=policies,
    )


# ============================================================
# Apply
# ============================================================

@router.post(
    "/{policy}",
    response_class=HTMLResponse,
)
async def update_recipient_policy(
    request: Request,
    policy: str,
    patterns: List[str] = Form(default=[]),
    actions: List[str] = Form(default=[]),
    messages: List[str] = Form(default=[]),
):

    guard = require_role(
        request,
        "security_admin",
        "smtp_admin",
    )

    if guard:
        return guard

    service = get_service()

    try:

        service.validate_policy(policy)

        entries = []

        for index, pattern in enumerate(patterns):

            action = (
                actions[index]
                if index < len(actions)
                else ""
            )

            message = (
                messages[index]
                if index < len(messages)
                else ""
            )

            entries.append({
                "pattern": pattern,
                "action": action,
                "message": message,
            })

        result = service.apply_policy(
            policy,
            entries,
        )

        # Keep your existing audit implementation here.
        #
        # Example:
        #
        # audit(
        #     request,
        #     action="UPDATE_RECIPIENT_POLICY",
        #     details={
        #         "policy": policy,
        #         "file": result["file_path"],
        #         "entries": result["entries"],
        #         "backup": result["backup_file"],
        #     },
        # )

        policies = service.get_all_policies()

        return render(
            request,
            "recipient_domains.html",
            policies=policies,
            success=(
                f"{policies[policy]['title']} "
                f"updated successfully."
            ),
        )

    except ValueError as exc:

        policies = service.get_all_policies()

        return render(
            request,
            "recipient_domains.html",
            policies=policies,
            error=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )