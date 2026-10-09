import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..config import settings
from .ad import authenticate_ad
from ..services.audit_log_service import audit

from datetime import datetime, timezone




logger = logging.getLogger(__name__)

router = APIRouter()


def page(request: Request, name: str, **context):
    from ..main import templates
    # Harmless for login.html/forbidden.html if they don't use it, and
    # covers the case where either one extends base.html later.
    context.setdefault("current_user", {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    })
    return templates.TemplateResponse(request, name, context)


@router.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    # If already authenticated, go directly to dashboard.
    if request.session.get("username"):
        return RedirectResponse("/dashboard", status_code=303)

    return page(request, "login.html", error=None)


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    username = username.strip()

    # ---------------------------------------------------------
    # Validate input
    # ---------------------------------------------------------
    if not username or not password:
        return page(request, "login.html", error="Username and password are required.")

    auth_mode = (settings.auth_mode or "").lower()
    user = None

    # ---------------------------------------------------------
    # Development authentication
    # ---------------------------------------------------------
    if auth_mode == "dev":
        # NOTE: this accepts ANY password for ANY username and grants
        # full security_admin access. It exists for local development
        # only. If this branch is ever reachable in production, that is
        # a critical misconfiguration, not a feature - the loud log line
        # below exists so it cannot pass unnoticed in application logs.
        logger.warning(
            "AUTH_MODE=dev: granting unauthenticated security_admin access "
            "to '%s'. This must never run against production.",
            username,
        )
        user = {
            "username": username,
            "role": "security_admin",
            "groups": ["DEV"],
        }

    # ---------------------------------------------------------
    # Active Directory authentication
    # ---------------------------------------------------------
    elif auth_mode == "ad":
        user = authenticate_ad(username, password)

    # ---------------------------------------------------------
    # Unsupported authentication mode
    # ---------------------------------------------------------
    else:
        logger.error("Login blocked: unsupported settings.auth_mode=%r", settings.auth_mode)
        return page(request, "login.html", error="Invalid authentication configuration.")

    # ---------------------------------------------------------
    # Authentication / authorization failed
    # ---------------------------------------------------------
    if not user:
        try:
            audit(request, "LOGIN", username, result="FAILED", error="Invalid credentials or not authorized")
        except Exception:
            logger.exception("Failed to write failed-login audit entry")

        return page(request, "login.html", error="Authentication or authorization failed.")

    # ---------------------------------------------------------
    # Create authenticated session
    # ---------------------------------------------------------
    request.session.clear()

#     request.session["username"] = user["username"]
#     request.session["role"] = user["role"]
#     request.session["groups"] = user.get("groups", [])
#
#     ------
    # ... inside login_post(), right where the session is populated:

    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    request.session["groups"] = user.get("groups", [])
    request.session["login_time"] = datetime.now(timezone.utc).isoformat()  # add this line


    try:
        audit(request, "LOGIN", user["username"], result="SUCCESS")
    except Exception:
        logger.exception("Failed to write successful-login audit entry")

    # ---------------------------------------------------------
    # Redirect to dashboard
    # ---------------------------------------------------------
    return RedirectResponse("/dashboard", status_code=303)

@router.api_route("/logout", methods=["GET", "POST"])
async def logout(request: Request):
    username = request.session.get("username")

    if username:
        try:
            audit(request, "LOGOUT", username, result="SUCCESS")
        except Exception:
            logger.exception("Failed to write logout audit entry")

    request.session.clear()

    return RedirectResponse("/login?logged_out=1", status_code=303)


@router.get("/forbidden", response_class=HTMLResponse)
async def forbidden(request: Request):
    return page(request, "forbidden.html")