import json
import logging
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class MailQueueError(Exception):
    """Raised for any mail queue read/write failure."""


class MailQueueService:
    def __init__(self, command_timeout: int = 15):
        self.command_timeout = command_timeout

    def _run(self, args: List[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                args, capture_output=True, text=True, timeout=self.command_timeout
            )
        except subprocess.TimeoutExpired as exc:
            logger.exception("Mail queue command timed out: %s", " ".join(args))
            raise MailQueueError(f"Command timed out: {' '.join(args)}") from exc
        except Exception as exc:
            logger.exception("Mail queue command failed to execute: %s", " ".join(args))
            raise MailQueueError(str(exc)) from exc

    def list_messages(self) -> List[Dict[str, Any]]:
        """
        Uses `postqueue -j` (JSON-lines queue listing, Postfix 3.1+)
        rather than parsing the plain-text `postqueue -p` table -
        far more reliable than regex-parsing a human-readable format.
        """
        result = self._run(["postqueue", "-j"])

        if result.returncode != 0:
            error = result.stderr.strip() or "postqueue -j failed"
            logger.error("postqueue -j failed: %s", error)
            raise MailQueueError(error)

        messages = []

        for line_number, line in enumerate(result.stdout.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping unparsable postqueue -j line %d", line_number)
                continue

            arrival_ts = entry.get("arrival_time")
            arrival_iso = None

            if arrival_ts is not None:
                try:
                    arrival_iso = datetime.fromtimestamp(arrival_ts, tz=timezone.utc).isoformat()
                except Exception:
                    arrival_iso = None

            recipients = entry.get("recipients", [])

            messages.append({
                "queue_id": entry.get("queue_id"),
                "queue_name": entry.get("queue_name"),
                "size": entry.get("message_size", 0),
                "arrival_time": arrival_ts,
                "arrival_iso": arrival_iso,
                "sender": entry.get("sender"),
                "recipients": recipients,
                "recipient_count": len(recipients),
                "delay_reasons": [
                    r.get("delay_reason") for r in recipients if r.get("delay_reason")
                ],
            })

        return messages

    def summary(self, messages: Optional[List[Dict[str, Any]]] = None) -> Dict[str, int]:
        if messages is None:
            messages = self.list_messages()

        counts = {
            "active": 0,
            "deferred": 0,
            "hold": 0,
            "incoming": 0,
            "corrupt": 0,
            "total": 0,
        }

        for msg in messages:
            name = msg.get("queue_name") or "unknown"
            counts["total"] += 1
            if name in counts:
                counts[name] += 1

        return counts

    def get_message(self, queue_id: str) -> Optional[Dict[str, Any]]:
        for msg in self.list_messages():
            if msg["queue_id"] == queue_id:
                return msg
        return None

    def get_message_headers(self, queue_id: str) -> str:
        """
        Returns headers only, via `postcat -h -q <id>`. Body content
        is deliberately excluded from this admin UI - headers are
        normally sufficient for delivery triage, and not rendering
        full message bodies avoids casually exposing user email
        content through a web interface with a broader access list
        (read_only role included) than "who can read a mail spool
        directly on the server."
        """
        result = self._run(["postcat", "-h", "-q", queue_id])

        if result.returncode != 0:
            error = result.stderr.strip() or f"Unable to read message {queue_id}"
            raise MailQueueError(error)

        return result.stdout

    def flush_queue(self) -> None:
        result = self._run(["postqueue", "-f"])

        if result.returncode != 0:
            error = result.stderr.strip() or "postqueue -f failed"
            raise MailQueueError(error)

    def delete_message(self, queue_id: str) -> None:
        result = self._run(["postsuper", "-d", queue_id])

        if result.returncode != 0:
            error = result.stderr.strip() or f"Failed to delete message {queue_id}"
            raise MailQueueError(error)

    def delete_queue(self, queue_name: str) -> None:
        """
        Bulk-deletes every message in one named queue (e.g. "deferred"),
        via `postsuper -d ALL <queue_name>`. Deliberately does not
        support an unscoped "all queues" option here - that command
        (`postsuper -d ALL` with no queue name) deletes active and
        incoming mail too, which is a much larger blast radius than
        clearing out stuck deferred mail. If you need that, it should
        be a separate, more heavily confirmed action.
        """
        valid_queues = {"active", "deferred", "hold", "incoming", "corrupt"}

        if queue_name not in valid_queues:
            raise MailQueueError(f"'{queue_name}' is not a valid queue name.")

        result = self._run(["postsuper", "-d", "ALL", queue_name])

        if result.returncode != 0:
            error = result.stderr.strip() or f"Failed to clear queue '{queue_name}'"
            raise MailQueueError(error)

    def hold_message(self, queue_id: str) -> None:
        result = self._run(["postsuper", "-h", queue_id])

        if result.returncode != 0:
            error = result.stderr.strip() or f"Failed to hold message {queue_id}"
            raise MailQueueError(error)

    def release_message(self, queue_id: str) -> None:
        result = self._run(["postsuper", "-H", queue_id])

        if result.returncode != 0:
            error = result.stderr.strip() or f"Failed to release message {queue_id}"
            raise MailQueueError(error)

    def requeue_message(self, queue_id: str) -> None:
        result = self._run(["postsuper", "-r", queue_id])

        if result.returncode != 0:
            error = result.stderr.strip() or f"Failed to requeue message {queue_id}"
            raise MailQueueError(error)