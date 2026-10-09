from fastapi import Request
from fastapi.responses import RedirectResponse

from .config import settings


# =========================================================
# Current User
# =========================================================

def current_user(request: Request):
    """
    Return the current authenticated user.

    DEV mode:
        Returns the development user.

    AD mode:
        Returns the username stored in the session.
    """

    # -----------------------------------------------------
    # DEV mode
    # -----------------------------------------------------

    if settings.auth_mode.lower() == "dev":

        return {
            "username": request.session.get("username", "dev_user"),
            "role": request.session.get("role", "security_admin"),
            "groups": request.session.get("groups", ["DEV"]),
        }

    # -----------------------------------------------------
    # Normal mode
    # -----------------------------------------------------

    username = request.session.get("username")

    if not username:
        return None

    return {
        "username": username,
        "role": request.session.get("role"),
        "groups": request.session.get("groups", []),
    }


# =========================================================
# Login Guard
# =========================================================

def require_login(request: Request):
    """
    Check whether the user is authenticated.

    DEV mode:
        Authentication is bypassed.

    AD mode:
        A valid username must exist in the session.
    """

    # -----------------------------------------------------
    # DEV mode
    # -----------------------------------------------------

    if settings.auth_mode.lower() == "dev":

        # Create a development session if one does not exist.
        if not request.session.get("username"):

            request.session["username"] = "dev_user"
            request.session["role"] = "security_admin"
            request.session["groups"] = ["DEV"]

        return None

    # -----------------------------------------------------
    # Normal authentication
    # -----------------------------------------------------

    if not request.session.get("username"):

        return RedirectResponse(
            "/login",
            status_code=303,
        )

    return None


# =========================================================
# Role Check
# =========================================================

def has_role(request: Request, *roles):
    """
    Check whether the current user has one of the
    required roles.
    """

    # -----------------------------------------------------
    # DEV mode
    # -----------------------------------------------------

    if settings.auth_mode.lower() == "dev":

        # DEV user has full Security Admin access.
        return "security_admin" in roles

    # -----------------------------------------------------
    # Normal mode
    # -----------------------------------------------------

    return request.session.get("role") in roles


# =========================================================
# Role Guard
# =========================================================

def require_role(request: Request, *roles):
    """
    Require authentication and one of the specified roles.
    """

    # -----------------------------------------------------
    # Authentication check
    # -----------------------------------------------------

    guard = require_login(request)

    if guard:
        return guard

    # -----------------------------------------------------
    # Authorization check
    # -----------------------------------------------------

    if not has_role(request, *roles):

        return RedirectResponse(
            "/forbidden",
            status_code=303,
        )

    return None

