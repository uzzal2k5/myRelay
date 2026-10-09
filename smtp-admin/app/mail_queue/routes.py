import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..common import require_role
from ..services.audit_service import audit
from ..services.mail_queue_service import MailQueueService, MailQueueError


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mail/queue", tags=["Mail Queue"])


def get_current_user(request: Request) -> dict:
    """
    Builds the current_user context object used by shared partials
    (topnav.html, sidebar.html). Kept in sync with the same helper
    duplicated across every other router in this app.
    """
    return {
        "username": request.session.get("username"),
        "role": request.session.get("role", "read_only"),
    }


def render(request, name, **ctx):
    from ..main import templates
    ctx.setdefault("current_user", get_current_user(request))
    return templates.TemplateResponse(request, name, ctx)


def get_service() -> MailQueueService:
    return MailQueueService()


def _is_editor(request: Request) -> bool:
    return request.session.get("role") in ("security_admin", "smtp_admin")


@router.get("", response_class=HTMLResponse)
async def mail_queue_page(request: Request, queue: str = "all", q: str = ""):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    service = get_service()
    error = None
    messages = []
    counts = {"active": 0, "deferred": 0, "hold": 0, "incoming": 0, "corrupt": 0, "total": 0}

    try:
        messages = service.list_messages()
        counts = service.summary(messages)
    except MailQueueError as exc:
        logger.warning("Failed to list mail queue: %s", exc)
        error = str(exc)

    if queue != "all":
        messages = [m for m in messages if m.get("queue_name") == queue]

    if q:
        needle = q.strip().lower()
        messages = [
            m for m in messages
            if needle in (m.get("sender") or "").lower()
            or any(needle in (r.get("address") or "").lower() for r in m.get("recipients", []))
            or needle in (m.get("queue_id") or "").lower()
        ]

    # Newest first
    messages.sort(key=lambda m: m.get("arrival_time") or 0, reverse=True)

    return render(
        request,
        "mail_queue.html",
        messages=messages,
        counts=counts,
        selected_queue=queue,
        search_query=q,
        is_editor=_is_editor(request),
        error=error,
    )


@router.get("/{queue_id}", response_class=HTMLResponse)
async def mail_queue_detail(request: Request, queue_id: str):
    guard = require_role(request, "security_admin", "smtp_admin", "read_only")
    if guard:
        return guard

    service = get_service()
    error = None
    message = None
    headers = None

    try:
        message = service.get_message(queue_id)
        if message is None:
            error = f"Message '{queue_id}' was not found in the queue. It may have already been delivered, deferred elsewhere, or deleted."
    except MailQueueError as exc:
        logger.warning("Failed to look up mail queue message %s: %s", queue_id, exc)
        error = str(exc)

    if message and not error:
        try:
            headers = service.get_message_headers(queue_id)
        except MailQueueError as exc:
            logger.warning("Failed to read headers for %s: %s", queue_id, exc)
            error = str(exc)

    return render(
        request,
        "mail_queue_detail.html",
        queue_id=queue_id,
        message=message,
        headers=headers,
        is_editor=_is_editor(request),
        error=error,
    )


@router.post("/flush")
async def mail_queue_flush(request: Request):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        service.flush_queue()

        try:
            audit(request, action="MAIL_QUEUE_FLUSH", object="mail_queue", result="SUCCESS")
        except Exception:
            logger.exception("Failed to write mail queue flush audit entry")

    except MailQueueError as exc:
        logger.warning("Mail queue flush failed: %s", exc)
        try:
            audit(request, action="MAIL_QUEUE_FLUSH", object="mail_queue", result="FAILED", error=str(exc))
        except Exception:
            logger.exception("Failed to write mail queue flush failure audit entry")

    return RedirectResponse(url="/mail/queue", status_code=303)


@router.post("/{queue_id}/delete")
async def mail_queue_delete(request: Request, queue_id: str):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        service.delete_message(queue_id)
        try:
            audit(request, action="MAIL_QUEUE_DELETE", object=queue_id, result="SUCCESS")
        except Exception:
            logger.exception("Failed to write mail queue delete audit entry")
    except MailQueueError as exc:
        logger.warning("Failed to delete mail queue message %s: %s", queue_id, exc)
        try:
            audit(request, action="MAIL_QUEUE_DELETE", object=queue_id, result="FAILED", error=str(exc))
        except Exception:
            logger.exception("Failed to write mail queue delete failure audit entry")

    return RedirectResponse(url="/mail/queue", status_code=303)


@router.post("/{queue_id}/hold")
async def mail_queue_hold(request: Request, queue_id: str):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        service.hold_message(queue_id)
        try:
            audit(request, action="MAIL_QUEUE_HOLD", object=queue_id, result="SUCCESS")
        except Exception:
            logger.exception("Failed to write mail queue hold audit entry")
    except MailQueueError as exc:
        logger.warning("Failed to hold mail queue message %s: %s", queue_id, exc)

    return RedirectResponse(url=f"/mail/queue/{queue_id}", status_code=303)


@router.post("/{queue_id}/release")
async def mail_queue_release(request: Request, queue_id: str):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        service.release_message(queue_id)
        try:
            audit(request, action="MAIL_QUEUE_RELEASE", object=queue_id, result="SUCCESS")
        except Exception:
            logger.exception("Failed to write mail queue release audit entry")
    except MailQueueError as exc:
        logger.warning("Failed to release mail queue message %s: %s", queue_id, exc)

    return RedirectResponse(url=f"/mail/queue/{queue_id}", status_code=303)


@router.post("/{queue_id}/requeue")
async def mail_queue_requeue(request: Request, queue_id: str):
    guard = require_role(request, "security_admin", "smtp_admin")
    if guard:
        return guard

    service = get_service()

    try:
        service.requeue_message(queue_id)
        try:
            audit(request, action="MAIL_QUEUE_REQUEUE", object=queue_id, result="SUCCESS")
        except Exception:
            logger.exception("Failed to write mail queue requeue audit entry")
    except MailQueueError as exc:
        logger.warning("Failed to requeue mail queue message %s: %s", queue_id, exc)

    return RedirectResponse(url=f"/mail/queue/{queue_id}", status_code=303)


@router.post("/clear")
async def mail_queue_clear(request: Request, queue_name: str = Form(...)):
    """
    Bulk-clears one named queue (typically 'deferred'). Restricted to
    security_admin only (not smtp_admin) since this is a higher-blast-
    radius action than any single-message operation on this page.
    """
    guard = require_role(request, "security_admin")
    if guard:
        return guard

    service = get_service()

    try:
        service.delete_queue(queue_name)
        try:
            audit(request, action="MAIL_QUEUE_CLEAR", object=queue_name, result="SUCCESS")
        except Exception:
            logger.exception("Failed to write mail queue clear audit entry")
    except MailQueueError as exc:
        logger.warning("Failed to clear queue '%s': %s", queue_name, exc)
        try:
            audit(request, action="MAIL_QUEUE_CLEAR", object=queue_name, result="FAILED", error=str(exc))
        except Exception:
            logger.exception("Failed to write mail queue clear failure audit entry")

    return RedirectResponse(url="/mail/queue", status_code=303)