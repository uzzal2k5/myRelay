from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..config import settings
from .ad import authenticate_ad


router = APIRouter()


# =========================================================
# Template Helper
# =========================================================

def page(request: Request, name: str, **context):
    """
    Render a Jinja2 template.
    """
    from ..main import templates

    return templates.TemplateResponse(
        request,
        name,
        context,
    )


# =========================================================
# Login
# =========================================================

@router.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    """
    Login page.

    In DEV mode:
        Authentication is bypassed and a development session
        is created automatically.

    In AD mode:
        Normal login page is displayed unless the user is
        already authenticated.
    """

    # -----------------------------------------------------
    # Development mode - bypass authentication
    # -----------------------------------------------------

    if settings.auth_mode.lower() == "dev":

        request.session["username"] = "dev_user"
        request.session["role"] = "security_admin"
        request.session["groups"] = ["DEV"]

        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    # -----------------------------------------------------
    # Already authenticated
    # -----------------------------------------------------

    if request.session.get("username"):
        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    # -----------------------------------------------------
    # Normal login page
    # -----------------------------------------------------

    return page(
        request,
        "login.html",
        error=None,
    )


# =========================================================
# Login POST
# =========================================================

@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = "",
    password: str = "",
):
    """
    Process login.

    DEV:
        Authentication is bypassed.

    AD:
        Username/password are validated against Active Directory.
    """

    # -----------------------------------------------------
    # Development mode - bypass authentication
    # -----------------------------------------------------

    if settings.auth_mode.lower() == "dev":

        request.session.clear()

        request.session["username"] = "dev_user"
        request.session["role"] = "security_admin"
        request.session["groups"] = ["DEV"]

        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    username = username.strip()

    if not username or not password:
        return page(
            request,
            "login.html",
            error="Username and password are required.",
        )

    # -----------------------------------------------------
    # Active Directory authentication
    # -----------------------------------------------------

    if settings.auth_mode.lower() == "ad":

        user = authenticate_ad(
            username,
            password,
        )

    # -----------------------------------------------------
    # Unsupported authentication mode
    # -----------------------------------------------------

    else:

        return page(
            request,
            "login.html",
            error="Invalid authentication configuration.",
        )

    # -----------------------------------------------------
    # Authentication / authorization failed
    # -----------------------------------------------------

    if not user:

        return page(
            request,
            "login.html",
            error="Authentication or authorization failed.",
        )

    # -----------------------------------------------------
    # Create authenticated session
    # -----------------------------------------------------

    request.session.clear()

    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    request.session["groups"] = user.get("groups", [])

    # -----------------------------------------------------
    # Redirect to dashboard
    # -----------------------------------------------------

    return RedirectResponse(
        "/dashboard",
        status_code=303,
    )


# =========================================================
# Logout
# =========================================================

@router.get("/logout")
async def logout(request: Request):
    """
    Clear the current user session and return to login.
    """

    request.session.clear()

    return RedirectResponse(
        "/login",
        status_code=303,
    )


# =========================================================
# Forbidden
# =========================================================

@router.get("/forbidden", response_class=HTMLResponse)
async def forbidden(request: Request):
    """
    Display the authorization/forbidden page.
    """

    return page(
        request,
        "forbidden.html",
    )

