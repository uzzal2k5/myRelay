"""
Delivery status reporting: turns parsed Postfix log activity into the
numbers an administrator actually asks about - did mail get delivered, to
whom did it fail, and why.

Counting is per RECIPIENT, not per message. A message to ten people is ten
delivery outcomes, and one slow recipient should not hide nine successes.
"""
import logging
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from .message_tracking_service import MessageRecord, MessageTrackingService


logger = logging.getLogger(__name__)

MAX_EVENTS_SHOWN = 200
TOP_N = 10
REASON_MAX_LENGTH = 140

VALID_STATUS_FILTERS = {"all", "sent", "deferred", "bounced", "rejected"}

_EMAIL_IN_BRACKETS = re.compile(r"<[^>\s]+@[^>\s]+>")
_BARE_EMAIL = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
_IP_ADDRESS = re.compile(r"\[?\b\d{1,3}(?:\.\d{1,3}){3}\b\]?")
_HOST_PREFIX = re.compile(r"^host\s+\S+\s+said:\s*", re.IGNORECASE)
_SPACES = re.compile(r"\s+")


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[1].lower() if "@" in address else "(none)"


def _to_float(value: Optional[str]) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def normalize_reason(detail: Optional[str]) -> str:
    """
    Reduce a free-text SMTP failure message to a stable label so that
    "550 ... <a@x.com>: User unknown" and "550 ... <b@x.com>: User unknown"
    count as the same problem instead of two.
    """
    if not detail:
        return "No detail logged"

    text = _HOST_PREFIX.sub("", detail)
    text = _EMAIL_IN_BRACKETS.sub("<address>", text)
    text = _BARE_EMAIL.sub("<address>", text)
    text = _IP_ADDRESS.sub("<ip>", text)
    text = _SPACES.sub(" ", text).strip()

    if len(text) > REASON_MAX_LENGTH:
        text = text[: REASON_MAX_LENGTH - 1].rstrip() + "…"

    return text or "No detail logged"


class DeliveryStatusService:
    def __init__(self, tracking: MessageTrackingService):
        self.tracking = tracking

    @staticmethod
    def _events_from(records: List[MessageRecord]) -> List[Dict[str, Any]]:
        """One event per recipient that has a delivery outcome."""
        events: List[Dict[str, Any]] = []

        for record in records:
            for recipient in record.recipients.values():
                if not recipient.status:
                    continue

                if record.is_reject:
                    detail, dsn = record.reject_reason, record.reject_code
                else:
                    detail, dsn = recipient.detail, recipient.dsn

                events.append({
                    "queue_id": record.queue_id,
                    "time": record.last_seen or record.first_seen,
                    "sender": record.sender,
                    "sasl_username": record.sasl_username,
                    "client": record.client,
                    "recipient": recipient.address,
                    "domain": _domain_of(recipient.address),
                    "status": "rejected" if record.is_reject else recipient.status,
                    "dsn": dsn,
                    "relay": recipient.relay,
                    "delay": _to_float(recipient.delay),
                    "detail": detail,
                    "reason": normalize_reason(detail),
                })

        return events

    @staticmethod
    def _summarize(events: List[Dict[str, Any]], in_progress: int) -> Dict[str, Any]:
        counts = Counter(e["status"] for e in events)
        sent = counts.get("sent", 0)
        deferred = counts.get("deferred", 0)
        bounced = counts.get("bounced", 0)
        rejected = counts.get("rejected", 0)

        # Success rate covers mail the relay accepted and then finished:
        # sent / (sent + bounced). Deferred mail is still retrying, so it is
        # neither a success nor a failure yet; submission-time rejects were
        # never accepted and usually reflect blocked senders rather than a
        # delivery fault, so both are reported separately instead of
        # skewing this number.
        finished = sent + bounced
        success_rate = round(sent / finished * 100, 1) if finished else None

        delays = [e["delay"] for e in events if e["status"] == "sent" and e["delay"] is not None]
        avg_delay = round(sum(delays) / len(delays), 1) if delays else None

        return {
            "sent": sent, "deferred": deferred, "bounced": bounced, "rejected": rejected,
            "in_progress": in_progress,
            "total": sent + deferred + bounced + rejected,
            "success_rate": success_rate,
            "avg_delay": avg_delay,
        }

    @staticmethod
    def _top_domains(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        stats: Dict[str, Counter] = defaultdict(Counter)
        for e in events:
            stats[e["domain"]][e["status"]] += 1

        rows = []
        for domain, c in stats.items():
            total = sum(c.values())
            problems = c["deferred"] + c["bounced"] + c["rejected"]
            rows.append({
                "domain": domain,
                "sent": c["sent"], "deferred": c["deferred"],
                "bounced": c["bounced"], "rejected": c["rejected"],
                "total": total,
                "problem_rate": round(problems / total * 100) if total else 0,
            })

        rows.sort(key=lambda r: (-r["total"], r["domain"]))
        return rows[:TOP_N]

    @staticmethod
    def _top_senders(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        stats: Dict[str, Counter] = defaultdict(Counter)
        for e in events:
            if e["status"] == "rejected":
                # Rejected mail was never authenticated or accepted, so
                # attributing it to a sending account would be misleading.
                continue
            stats[e["sasl_username"] or e["sender"] or "(unknown)"][e["status"]] += 1

        rows = [
            {
                "sender": who,
                "sent": c["sent"], "deferred": c["deferred"], "bounced": c["bounced"],
                "total": sum(c.values()),
            }
            for who, c in stats.items()
        ]
        rows.sort(key=lambda r: (-r["total"], r["sender"]))
        return rows[:TOP_N]

    @staticmethod
    def _top_issues(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        grouped: Dict[tuple, Dict[str, Any]] = {}

        for e in events:
            if e["status"] == "sent":
                continue

            entry = grouped.setdefault((e["status"], e["dsn"] or "", e["reason"]), {
                "status": e["status"], "dsn": e["dsn"], "reason": e["reason"],
                "count": 0, "domains": Counter(), "last_seen": None,
            })
            entry["count"] += 1
            entry["domains"][e["domain"]] += 1
            # Events arrive newest-first, so the first one seen is the latest.
            entry["last_seen"] = entry["last_seen"] or e["time"]

        rows = [
            {
                "status": g["status"], "dsn": g["dsn"], "reason": g["reason"],
                "count": g["count"],
                "domains": [d for d, _ in g["domains"].most_common(3)],
                "last_seen": g["last_seen"],
            }
            for g in grouped.values()
        ]
        rows.sort(key=lambda r: (-r["count"], r["reason"]))
        return rows[:TOP_N]

    def get_report(self, lines: int = 5000, status: str = "all", query: str = "") -> Dict[str, Any]:
        records = self.tracking.get_records(limit=lines)
        all_events = self._events_from(records)

        in_progress = sum(1 for r in records if not r.is_reject and r.overall_status == "in_progress")

        # Aggregates always describe the whole window; only the event list
        # responds to the status/search filters, so the headline numbers
        # don't shift while someone is just narrowing a table.
        summary = self._summarize(all_events, in_progress)

        events = all_events
        if status in VALID_STATUS_FILTERS and status != "all":
            events = [e for e in events if e["status"] == status]

        needle = (query or "").strip().lower()
        if needle:
            def matches(e: Dict[str, Any]) -> bool:
                haystack = " ".join(filter(None, [
                    e["queue_id"], e["recipient"], e["sender"], e["sasl_username"],
                    e["domain"], e["detail"], e["relay"], e["client"],
                ])).lower()
                return needle in haystack

            events = [e for e in events if matches(e)]

        starts = [r.first_seen for r in records if r.first_seen]
        ends = [r.last_seen for r in records if r.last_seen]

        return {
            "summary": summary,
            "top_issues": self._top_issues(all_events),
            "top_domains": self._top_domains(all_events),
            "top_senders": self._top_senders(all_events),
            "events": events[:MAX_EVENTS_SHOWN],
            "events_total": len(events),
            "events_truncated": len(events) > MAX_EVENTS_SHOWN,
            "period_start": min(starts) if starts else None,
            "period_end": max(ends) if ends else None,
            "record_count": len(records),
        }