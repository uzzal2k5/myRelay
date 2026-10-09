from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from ..config import settings
from .ad import authenticate_ad


router = APIRouter()


def page(request: Request, name: str, **context):
    from ..main import templates
    return templates.TemplateResponse(
        request,
        name,
        context,
    )


@router.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    # If already authenticated, go directly to dashboard.
    if request.session.get("username"):
        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    return page(
        request,
        "login.html",
        error=None,
    )


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
        return page(
            request,
            "login.html",
            error="Username and password are required.",
        )

    # ---------------------------------------------------------
    # Development authentication
    # ---------------------------------------------------------
    if settings.auth_mode.lower() == "dev":

        user = {
            "username": username,
            "role": "security_admin",
            "groups": ["DEV"],
        }

    # ---------------------------------------------------------
    # Active Directory authentication
    # ---------------------------------------------------------
    elif settings.auth_mode.lower() == "ad":

        user = authenticate_ad(
            username,
            password,
        )

    # ---------------------------------------------------------
    # Unsupported authentication mode
    # ---------------------------------------------------------
    else:
        return page(
            request,
            "login.html",
            error="Invalid authentication configuration.",
        )

    # ---------------------------------------------------------
    # Authentication / authorization failed
    # ---------------------------------------------------------
    if not user:
        return page(
            request,
            "login.html",
            error="Authentication or authorization failed.",
        )

    # ---------------------------------------------------------
    # Create authenticated session
    # ---------------------------------------------------------
    request.session.clear()

    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    request.session["groups"] = user.get("groups", [])

    # ---------------------------------------------------------
    # Redirect to dashboard
    # ---------------------------------------------------------
    return RedirectResponse(
        "/dashboard",
        status_code=303,
    )


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()

    return RedirectResponse(
        "/login",
        status_code=303,
    )


@router.get("/forbidden", response_class=HTMLResponse)
async def forbidden(request: Request):
    return page(
        request,
        "forbidden.html",
    )