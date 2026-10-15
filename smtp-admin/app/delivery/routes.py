import logging

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse

from ..common import require_role
from ..services.delivery_status_service import VALID_STATUS_FILTERS, DeliveryStatusService
from ..services.message_tracking_service import MessageTrackingError, build_tracking_service


logger = logging.getLogger(__name__)

router = APIRouter()

# The window is a number of log LINES, not a time range - a busy relay
# produces many lines per message, so the page states the period actually
# covered rather than implying "last N hours".
WINDOW_CHOICES = [2000, 5000, 20000, 50000]
DEFAULT_WINDOW = 5000


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    })
    return templates.TemplateResponse(request, name, ctx)


def _empty_report() -> dict:
    return {
        "summary": {
            "sent": 0, "deferred": 0, "bounced": 0, "rejected": 0, "in_progress": 0,
            "total": 0, "success_rate": None, "avg_delay": None,
        },
        "top_issues": [], "top_domains": [], "top_senders": [],
        "events": [], "events_total": 0, "events_truncated": False,
        "period_start": None, "period_end": None, "record_count": 0,
    }


@router.get("/delivery", response_class=HTMLResponse)
async def delivery_page(request: Request, status: str = "all", q: str = "", lines: int = DEFAULT_WINDOW):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    if status not in VALID_STATUS_FILTERS:
        status = "all"
    if lines not in WINDOW_CHOICES:
        lines = DEFAULT_WINDOW
    q = q.strip()[:200]

    service = DeliveryStatusService(build_tracking_service())
    report = _empty_report()
    error = None

    try:
        # journalctl / log parsing is blocking; keep it off the event loop.
        report = await run_in_threadpool(service.get_report, lines, status, q)
    except MessageTrackingError as exc:
        logger.warning("Delivery status could not read the mail log: %s", exc)
        error = str(exc)
    except Exception:
        logger.exception("Unexpected error building delivery status report")
        error = "The delivery report failed unexpectedly. See the application log for details."

    return render(
        request,
        "delivery.html",
        report=report,
        status=status,
        search_query=q,
        lines=lines,
        window_choices=WINDOW_CHOICES,
        error=error,
    )