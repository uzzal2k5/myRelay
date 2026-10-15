"""
Reads Postfix's own log output and groups the lines that share a queue ID
into one record per message. This does not read message bodies - only what
Postfix itself logs (envelope sender/recipient, size, delivery status).

Two log sources are supported:
  - journalctl -u <unit>   (the default on OEL 9 / systemd-only hosts)
  - a plain log file (e.g. /var/log/maillog), for hosts using rsyslog

Which one is correct for a given server is not known here - see
build_tracking_service() and the settings it reads.
"""
import logging
import re
import subprocess
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


logger = logging.getLogger(__name__)

DEFAULT_LOG_LINES = 3000
MAX_LOG_LINES = 50000
DEFAULT_UNIT = "postfix"
DEFAULT_LOG_FILE = "/var/log/maillog"
MAX_RECORDS = 1000  # a 50k-line pull must not build an unbounded dict

# Postfix queue IDs come in two shapes: short hex IDs (e.g. "A1B2C3D4E5",
# the default) and long IDs (enable_long_queue_ids=yes, e.g. "4XQ3k61Z2zYwb")
# which use a wider alphabet. Both always contain at least one digit, which
# is what distinguishes them from the words that also precede a colon on
# queue-less lines ("NOQUEUE:", "warning:", "statistics:", "fatal:").
QUEUE_ID_PATTERN = r"(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{6,20}"
NON_QUEUE_WORDS = {"noqueue", "warning", "statistics", "fatal", "panic", "error"}

# journalctl -o short-iso: "2026-10-04T09:15:10+0600 host proc[pid]: rest"
# traditional syslog:      "Oct  4 09:15:10 host proc[pid]: rest"
# The timestamp is matched explicitly in one of these two shapes: a generic
# "\S+ plus optional extra tokens" pattern backtracks into the host/process
# fields and corrupts every field after it.
LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>postfix(?:/\S+)?)\[(?P<pid>\d+)\]:\s+"
    r"(?P<rest>.*)$"
)

QID_PREFIX_RE = re.compile(rf"^({QUEUE_ID_PATTERN}):\s*(.*)$")

# key=value, where a value may be <...>, (...), or a bare token. Bare tokens
# stop at a comma so "dsn=2.0.0," does not capture the trailing comma.
KV_RE = re.compile(r"(\w[\w\-]*)=(<[^>]*>|\([^)]*\)|[^\s,]+)")

NOQUEUE_REJECT_RE = re.compile(r"^NOQUEUE:\s*(reject|reject_warning):\s*(.*)$", re.IGNORECASE)


def _strip_wrap(value: str) -> str:
    if len(value) >= 2 and value[0] == "<" and value[-1] == ">":
        return value[1:-1]
    if len(value) >= 2 and value[0] == "(" and value[-1] == ")":
        return value[1:-1]
    return value


def _parse_kv(text: str) -> Dict[str, str]:
    return {k: _strip_wrap(v) for k, v in KV_RE.findall(text)}


@dataclass
class Recipient:
    address: str
    status: Optional[str] = None
    relay: Optional[str] = None
    delay: Optional[str] = None
    dsn: Optional[str] = None
    detail: Optional[str] = None


@dataclass
class MessageRecord:
    queue_id: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    client: Optional[str] = None
    sasl_username: Optional[str] = None
    message_id: Optional[str] = None
    sender: Optional[str] = None
    size: Optional[str] = None
    recipients: Dict[str, Recipient] = field(default_factory=dict)
    removed: bool = False
    is_reject: bool = False
    reject_code: Optional[str] = None
    reject_reason: Optional[str] = None
    raw_lines: List[str] = field(default_factory=list)

    @property
    def overall_status(self) -> str:
        if self.is_reject:
            return "rejected"
        statuses = {r.status for r in self.recipients.values() if r.status}
        if not statuses:
            return "in_progress"
        if "bounced" in statuses:
            return "bounced"
        # One sent + one deferred recipient reads as "deferred": the message
        # still has delivery pending.
        if "deferred" in statuses:
            return "deferred"
        if statuses == {"sent"}:
            return "sent"
        return "mixed"


class MessageTrackingError(Exception):
    """Raised when the log source could not be read."""


class MessageTrackingService:
    def __init__(
        self,
        unit: Optional[str] = None,
        log_file: Optional[str] = None,
        use_journalctl: Optional[bool] = None,
        command_timeout: int = 20,
        line_source: Optional[Callable[[int], List[str]]] = None,
    ):
        """
        `line_source`, if given, replaces the real journalctl/file read with
        a function `int -> list[str]`. Tests use it; it also lets log
        retrieval come from somewhere else entirely without changing the
        parsing.
        """
        self.unit = unit or DEFAULT_UNIT
        self.log_file = log_file or DEFAULT_LOG_FILE
        self.use_journalctl = True if use_journalctl is None else use_journalctl
        self.command_timeout = command_timeout
        self._line_source = line_source

    # -----------------------------------------------------------------
    # Reading
    # -----------------------------------------------------------------

    def _read_lines(self, limit: int) -> List[str]:
        if self._line_source:
            return self._line_source(limit)
        if self.use_journalctl:
            return self._read_from_journalctl(limit)
        return self._read_from_file(limit)

    def _read_from_journalctl(self, limit: int) -> List[str]:
        args = ["journalctl", "-u", self.unit, "-n", str(limit), "--no-pager", "-o", "short-iso"]
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=self.command_timeout)
        except subprocess.TimeoutExpired as exc:
            raise MessageTrackingError(f"journalctl timed out after {self.command_timeout}s") from exc
        except FileNotFoundError as exc:
            raise MessageTrackingError(
                "journalctl was not found on this host. If logs come from a file instead, "
                "set the mail log source to a file path."
            ) from exc
        except Exception as exc:
            raise MessageTrackingError(str(exc)) from exc

        if result.returncode != 0:
            raise MessageTrackingError(result.stderr.strip() or "journalctl failed")

        # journalctl exits 0 with an empty result when the account may not
        # read the journal, so an empty read has to be checked for this.
        stderr = result.stderr.lower()
        if "insufficient permissions" in stderr or "not seeing messages from other users" in stderr:
            raise MessageTrackingError(
                "The portal's service account is not allowed to read the system journal, so no "
                "mail log lines are visible. Add it to the systemd-journal group "
                "(usermod -aG systemd-journal <service account>) and restart the portal."
            )

        return result.stdout.splitlines()

    def _read_from_file(self, limit: int) -> List[str]:
        try:
            with open(self.log_file, "r", encoding="utf-8", errors="replace") as f:
                # Keep only the last `limit` lines in memory, so a multi-GB
                # log is never read in full just to take its tail.
                return [line.rstrip("\n") for line in deque(f, maxlen=limit)]
        except FileNotFoundError as exc:
            raise MessageTrackingError(f"Log file not found: {self.log_file}") from exc
        except PermissionError as exc:
            raise MessageTrackingError(
                f"Permission denied reading {self.log_file}. "
                "The portal's service account needs read access to it."
            ) from exc
        except Exception as exc:
            raise MessageTrackingError(str(exc)) from exc

    # -----------------------------------------------------------------
    # Parsing
    # -----------------------------------------------------------------

    def _parse(self, lines: List[str]) -> List[MessageRecord]:
        records: Dict[str, MessageRecord] = {}
        order: List[str] = []
        reject_counter = 0

        def get_record(qid: str) -> MessageRecord:
            if qid not in records:
                if len(records) >= MAX_RECORDS:
                    # Lines arrive oldest-first, so `order[0]` is the oldest.
                    records.pop(order.pop(0), None)
                records[qid] = MessageRecord(queue_id=qid)
                order.append(qid)
            return records[qid]

        for line in lines:
            m = LINE_RE.match(line)
            if not m:
                continue

            ts = m.group("ts")
            rest = m.group("rest")

            qid_match = QID_PREFIX_RE.match(rest)
            if qid_match and qid_match.group(1).lower() in NON_QUEUE_WORDS:
                qid_match = None

            if qid_match:
                qid, body = qid_match.group(1), qid_match.group(2)
                record = get_record(qid)
                record.raw_lines.append(line)
                record.first_seen = record.first_seen or ts
                record.last_seen = ts

                if body == "removed":
                    record.removed = True
                    continue

                kv = _parse_kv(body)

                if "client" in kv and record.sender is None:
                    record.client = kv.get("client")
                    record.sasl_username = kv.get("sasl_username")

                if "message-id" in kv:
                    record.message_id = kv["message-id"]

                if body.startswith("from="):
                    record.sender = kv.get("from") or record.sender
                    record.size = kv.get("size") or record.size

                if body.startswith("to="):
                    address = kv.get("to", "")
                    recipient = record.recipients.setdefault(address, Recipient(address=address))
                    recipient.status = kv.get("status") or recipient.status
                    recipient.relay = kv.get("relay") or recipient.relay
                    recipient.delay = kv.get("delay") or recipient.delay
                    recipient.dsn = kv.get("dsn") or recipient.dsn

                    detail_match = re.search(r"status=\S+\s*\((.*)\)\s*$", body)
                    if detail_match:
                        recipient.detail = detail_match.group(1)

                continue

            # No queue ID: either a NOQUEUE reject (mail refused before it
            # was queued) or a connect/disconnect/warning line with nothing
            # to correlate.
            reject_match = NOQUEUE_REJECT_RE.match(rest)
            if reject_match:
                reject_counter += 1
                detail = reject_match.group(2)
                kv = _parse_kv(detail)

                # The SMTP reply code sits inside the detail text
                # ("...: 554 5.7.1 <addr>: Relay access denied; ..."),
                # not at the start of it.
                code_match = re.search(r"\b(\d{3})\s+\d\.\d\.\d\b", detail)

                record = get_record(f"NOQUEUE-{reject_counter}")
                record.is_reject = True
                record.first_seen = ts
                record.last_seen = ts
                record.raw_lines.append(line)
                record.sender = kv.get("from")
                if kv.get("to"):
                    record.recipients[kv["to"]] = Recipient(address=kv["to"], status="rejected")
                record.client = self._extract_client(detail)
                record.reject_reason = detail[:300]
                if code_match:
                    record.reject_code = code_match.group(1)

        return [records[qid] for qid in order]

    @staticmethod
    def _extract_client(text: str) -> Optional[str]:
        m = re.search(r"from\s+(\S+\[[^\]]+\])", text)
        return m.group(1) if m else None

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def get_records(self, limit: int = DEFAULT_LOG_LINES) -> List[MessageRecord]:
        """Parsed records for the last `limit` log lines, newest first."""
        limit = max(1, min(limit, MAX_LOG_LINES))
        records = self._parse(self._read_lines(limit))
        records.reverse()
        return records


def build_tracking_service() -> MessageTrackingService:
    """
    Builds the service from application settings. Each attribute is read with
    getattr + a default, so a missing setting falls back to the OEL 9 default
    (journalctl, postfix unit) instead of crashing the app.
    """
    from ..config import settings

    return MessageTrackingService(
        unit=getattr(settings, "postfix_unit", None),
        log_file=getattr(settings, "mail_log_path", None),
        use_journalctl=getattr(settings, "mail_log_use_journalctl", None),
    )