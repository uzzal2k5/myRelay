import logging
import subprocess

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..common import require_login
from ..config import settings
from ..services.redis_service import RedisService
from ..services.smtp_policy_systemd_service import SmtpPolicySystemdService


logger = logging.getLogger(__name__)

router = APIRouter()


def render(request, name, **ctx):
    from ..main import templates
    return templates.TemplateResponse(request, name, ctx)


def fixed_command(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=10)


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Authentication
    guard = require_login(request)
    if guard:
        return guard

    # Current authenticated user
    current_user = getattr(request.state, "user", None)

    # Postfix service status
    try:
        postfix = fixed_command(["systemctl", "is-active", "postfix"])
        postfix_status = (
            postfix.stdout.strip()
            if postfix.returncode == 0
            else postfix.stderr.strip() or "INACTIVE"
        )
    except Exception:
        logger.exception("Failed to check Postfix status for dashboard")
        postfix_status = "UNKNOWN"

    # Redis status
    try:
        redis_ok = RedisService().ping()
        redis_status = "UP" if redis_ok else "DOWN"
    except Exception:
        logger.exception("Failed to check Redis status for dashboard")
        redis_status = "DOWN"

    # SMTP Policy status
    try:
        smtp_policy_status = SmtpPolicySystemdService().get_status().get("active", "unknown")
    except Exception:
        logger.exception("Failed to fetch SMTP policy service status for dashboard")
        smtp_policy_status = "unknown"

    # Mail queue
    try:
        queue = fixed_command(["postqueue", "-p"])
        queue_text = (
            queue.stdout
            if queue.returncode == 0
            else queue.stderr or "Unable to retrieve mail queue."
        )
    except Exception as exc:
        logger.exception("Failed to retrieve mail queue for dashboard")
        queue_text = f"Unable to retrieve mail queue: {exc}"

    # Render dashboard
    return render(
        request,
        "dashboard.html",
        current_user=current_user,
        postfix_status=postfix_status,
        redis_status=redis_status,
        smtp_policy_status=smtp_policy_status,
        queue=queue_text[-4000:],
    )