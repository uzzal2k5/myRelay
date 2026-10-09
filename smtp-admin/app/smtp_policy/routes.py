import logging
from typing import List

from fastapi import (
    APIRouter,
    Form,
    HTTPException,
    Request,
)
from fastapi.responses import HTMLResponse, JSONResponse

from ..common import require_role
from ..services.smtp_policy_service import SmtpPolicyService
from ..services.smtp_policy_systemd_service import SmtpPolicySystemdService
from ..services.smtp_policy_test_service import SmtpPolicyTestService


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/smtp/policy",
    tags=["SMTP Policy"],
)


def get_systemd_service():
    return SmtpPolicySystemdService()


def get_policy_test_service():
    return SmtpPolicyTestService()


def get_service():
    return SmtpPolicyService()


def require_policy_admin(request):
    return require_role(request, "security_admin", "smtp_admin")


def get_current_user(request: Request) -> dict:
    """
    Builds the current_user context object used by shared partials
    (topnav.html, sidebar.html).

    NOTE: assumes the session stores "username" and "role" keys set
    at login time. Keep this in sync with the same helper in
    certificates.py until this is centralized in one shared module.
    """
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }


def render(request, name, **ctx):
    from ..main import templates

    ctx.setdefault("current_user", get_current_user(request))
    return templates.TemplateResponse(request, name, ctx)


@router.get("/service/status")
async def policy_service_status(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    try:
        return JSONResponse(get_systemd_service().get_status())
    except Exception as exc:
        logger.exception("Failed to fetch SMTP policy service status")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/service/{action}")
async def policy_service_action(request: Request, action: str):
    guard = require_policy_admin(request)
    if guard:
        return guard

    service = get_systemd_service()

    actions = {
        "start": service.start,
        "stop": service.stop,
        "restart": service.restart,
        "enable": service.enable,
    }

    operation = actions.get(action)

    if operation is None:
        raise HTTPException(status_code=400, detail="Unsupported service action")

    try:
        result = operation()

        # TODO: record action/result using the existing audit()
        # function after confirming its signature.

        return JSONResponse({
            "success": True,
            "action": action,
            "status": result,
        })

    except Exception as exc:
        logger.exception("SMTP policy service action '%s' failed", action)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/test/simulate")
async def simulate_policy(request: Request, username: str = Form(...)):
    guard = require_policy_admin(request)
    if guard:
        return guard

    try:
        service = get_service()
        result = service.simulate_policy(username)

        # TODO: audit simulation result and administrator identity.

        return JSONResponse({
            "success": True,
            "test_type": "simulation",
            "result": result,
        })

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("SMTP policy simulation failed for %s", username)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/test/live")
async def live_policy_test(request: Request, username: str = Form(...)):
    guard = require_policy_admin(request)
    if guard:
        return guard

    try:
        service = get_policy_test_service()
        response = service.test_listener(username)

        # TODO: audit live test and returned response.

        return JSONResponse({
            "success": True,
            "test_type": "live_listener",
            "warning": (
                "A successful live test may increment "
                "the user's SMTP rate counters."
            ),
            "response": response,
        })

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Live SMTP policy test failed for %s", username)
        raise HTTPException(status_code=500, detail=str(exc))


def _collect_usage(service: SmtpPolicyService, users: list) -> dict:
    """
    Shared helper: builds the {username: usage} map used across the
    page render, save, and delete handlers, so a Redis hiccup for one
    user degrades gracefully (shows N/A in the UI) instead of taking
    down the whole page.
    """
    usage = {}
    for user in users:
        try:
            current = service.get_current_usage(user["username"])
            usage[user["username"]] = current
        except Exception:
            logger.warning(
                "Could not fetch current usage for SMTP policy user %s",
                user["username"],
                exc_info=True,
            )
            usage[user["username"]] = None
    return usage


@router.get("", response_class=HTMLResponse)
async def smtp_policy_page(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    service = get_service()

    try:
        users = service.list_users()
        redis_ok = service.ping()
        usage = _collect_usage(service, users)

        return render(
            request,
            "smtp_policy.html",
            users=users,
            usage=usage,
            redis_ok=redis_ok,
        )

    except Exception as exc:
        logger.exception("Failed to load SMTP policy page")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/save", response_class=HTMLResponse)
async def save_smtp_policy(
    request: Request,
    username: str = Form(...),
    enabled: str = Form("0"),
    minute_limit: int = Form(...),
    hour_limit: int = Form(...),
    day_limit: int = Form(...),
):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        normalized_username = service.validate_username(username)
        old_config = service.get_user_config(normalized_username)

        new_config = service.save_user_config(
            username=normalized_username,
            enabled=enabled == "1",
            minute_limit=minute_limit,
            hour_limit=hour_limit,
            day_limit=day_limit,
        )

        # Existing audit service should be integrated here.
        #
        # Example:
        #
        # audit(
        #     request,
        #     action="SMTP_POLICY_UPDATE",
        #     details={
        #         "username": normalized_username,
        #         "old": old_config,
        #         "new": new_config,
        #     },
        # )

        users = service.list_users()
        usage = _collect_usage(service, users)

        return render(
            request,
            "smtp_policy.html",
            users=users,
            usage=usage,
            redis_ok=service.ping(),
            success=f"SMTP policy for {normalized_username} updated successfully.",
        )

    except ValueError as exc:
        users = service.list_users()
        return render(
            request,
            "smtp_policy.html",
            users=users,
            usage=_collect_usage(service, users),
            redis_ok=service.ping(),
            error=str(exc),
        )

    except Exception as exc:
        logger.exception("Failed to save SMTP policy for %s", username)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/delete", response_class=HTMLResponse)
async def delete_smtp_policy(request: Request, username: str = Form(...)):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        validated_username = service.validate_username(username)
        deleted = service.delete_user(validated_username)

        # Integrate with existing audit service here.

        users = service.list_users()
        usage = _collect_usage(service, users)

        return render(
            request,
            "smtp_policy.html",
            users=users,
            usage=usage,
            redis_ok=service.ping(),
            success=(
                f"SMTP policy for {validated_username} "
                f"was {'deleted' if deleted else 'not found'}."
            ),
        )

    except ValueError as exc:
        users = service.list_users()
        return render(
            request,
            "smtp_policy.html",
            users=users,
            usage=_collect_usage(service, users),
            redis_ok=service.ping(),
            error=str(exc),
        )

    except Exception as exc:
        logger.exception("Failed to delete SMTP policy for %s", username)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/usage/{username:path}", response_class=HTMLResponse)
async def smtp_policy_usage(request: Request, username: str):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    service = get_service()

    try:
        validated_username = service.validate_username(username)
        usage = service.get_current_usage(validated_username)

        if usage is None:
            raise HTTPException(status_code=404, detail="SMTP policy user not found")

        return render(
            request,
            "smtp_policy.html",
            users=service.list_users(),
            usage={validated_username: usage},
            redis_ok=service.ping(),
            selected_user=validated_username,
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception("Failed to load usage for SMTP policy user %s", username)
        raise HTTPException(status_code=500, detail=str(exc))