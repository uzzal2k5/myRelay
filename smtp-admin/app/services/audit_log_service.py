import csv
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

from ..config import settings


logger = logging.getLogger(__name__)

EXPORT_CSV_COLUMNS = [
    "timestamp",
    "username",
    "role",
    "action",
    "object",
    "result",
    "source_ip",
]


class AuditLogError(Exception):
    """Raised when an audit log read/export operation fails."""


class AuditLogService:
    """
    Central service for writing, reading, filtering and exporting
    the SMTP Admin Portal audit log.

    All routers should use the shared `audit_log_service` instance
    defined at the bottom of this module.
    """

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path or settings.audit_log_path

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def log(
        self,
        request,
        action: str,
        object_name: Optional[str] = None,
        *,
        object: Optional[str] = None,  # noqa: A002
        old_value=None,
        new_value=None,
        result: str = "SUCCESS",
        error: Optional[str] = None,
        details: Optional[dict] = None,
        **extra,
    ) -> None:
        """
        Write one audit entry as JSONL.

        Audit logging must never break the actual application operation.
        Any write failure is logged and swallowed.
        """

        resolved_object = (
            object_name if object_name is not None else object
        )

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": request.session.get("username"),
            "role": request.session.get("role"),
            "source_ip": request.client.host if request.client else None,
            "action": action,
            "object": resolved_object,
            "old_value": old_value,
            "new_value": new_value,
            "result": result,
            "error": error,
        }

        if details:
            record["details"] = details

        if extra:
            record.update(extra)

        try:
            path = Path(self.log_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with path.open("a", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                    )
                    + "\n"
                )

        except Exception:
            logger.exception(
                "Failed to write audit log entry: %s",
                action,
            )

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_line(line: str) -> dict:
        """
        Parse one JSON audit-log line.

        Malformed lines are preserved as `_raw` so one corrupt entry
        cannot break the audit page or export.
        """

        try:
            entry = json.loads(line)

            if not isinstance(entry, dict):
                raise ValueError(
                    "Audit line did not decode to an object"
                )

            entry["_raw"] = line
            return entry

        except Exception:
            return {
                "_raw": line,
                "_parse_error": True,
            }

    def read_recent(self, limit: int = 200) -> List[dict]:
        """
        Read the most recent audit entries.

        Returned newest entries come first.
        """

        try:
            path = Path(self.log_path)

            if not path.exists():
                return []

            if limit <= 0:
                return []

            lines = path.read_text(
                encoding="utf-8"
            ).splitlines()

            lines = lines[-limit:]

        except Exception as exc:
            logger.exception(
                "Failed to read audit log at %s",
                self.log_path,
            )
            raise AuditLogError(str(exc)) from exc

        return [
            self._parse_line(line)
            for line in reversed(lines)
        ]

    def read_all(self) -> List[dict]:
        """
        Read and parse the complete audit log.
        """

        try:
            path = Path(self.log_path)

            if not path.exists():
                return []

            lines = path.read_text(
                encoding="utf-8"
            ).splitlines()

        except Exception as exc:
            logger.exception(
                "Failed to read full audit log at %s",
                self.log_path,
            )
            raise AuditLogError(str(exc)) from exc

        return [
            self._parse_line(line)
            for line in lines
        ]

    # ------------------------------------------------------------------
    # Compatibility helpers
    # ------------------------------------------------------------------

    def read_recent_entries(
        self,
        limit: int = 200,
    ) -> List[dict]:
        """
        Backward-compatible alias used by older audit routes.
        """

        return self.read_recent(limit=limit)

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------
    @staticmethod
    def search_entries(
        entries: Iterable[dict],
        query: Optional[str],
    ) -> List[dict]:
        """
        Search audit entries across common audit fields.

        Matching is case-insensitive and searches:
        username, role, action, object, result, source_ip,
        error and details.
        """

        if not query or not query.strip():
            return list(entries)

        search_text = query.strip().lower()
        matched = []

        searchable_fields = (
            "timestamp",
            "username",
            "role",
            "action",
            "object",
            "result",
            "source_ip",
            "error",
            "details",
        )

        for entry in entries:
            if entry.get("_parse_error"):
                continue

            for field in searchable_fields:
                value = entry.get(field)

                if value is None:
                    continue

                if isinstance(value, (dict, list)):
                    value = json.dumps(
                        value,
                        ensure_ascii=False,
                        default=str,
                    )

                if search_text in str(value).lower():
                    matched.append(entry)
                    break

        return matched
    @staticmethod
    def filter_by_action_keywords(
        entries: Iterable[dict],
        keywords: List[str],
    ) -> List[dict]:

        lowered_keywords = [
            k.lower()
            for k in keywords
            if k
        ]

        if not lowered_keywords:
            return list(entries)

        matched = []

        for entry in entries:

            if entry.get("_parse_error"):
                continue

            action = (
                entry.get("action") or ""
            ).lower()

            if any(
                keyword in action
                for keyword in lowered_keywords
            ):
                matched.append(entry)

        return matched

    @staticmethod
    def search(
        entries: Iterable[dict],
        query: Optional[str],
    ) -> List[dict]:

        if not query:
            return list(entries)

        needle = query.strip().lower()

        if not needle:
            return list(entries)

        matched = []

        for entry in entries:

            haystack = " ".join(
                [
                    str(entry.get("username", "")),
                    str(entry.get("action", "")),
                    str(entry.get("object", "")),
                    str(entry.get("source_ip", "")),
                ]
            ).lower()

            if needle in haystack:
                matched.append(entry)

        return matched

    @staticmethod
    def filter_by_date_range(
        entries: Iterable[dict],
        start_date: Optional[str],
        end_date: Optional[str],
    ) -> List[dict]:

        if not start_date and not end_date:
            return list(entries)

        try:
            start_dt = (
                datetime.fromisoformat(start_date)
                if start_date
                else None
            )
        except ValueError:
            start_dt = None

        try:
            end_dt = (
                datetime.fromisoformat(end_date)
                if end_date
                else None
            )
        except ValueError:
            end_dt = None

        matched = []

        for entry in entries:

            raw_ts = entry.get("timestamp")

            if not raw_ts:
                continue

            try:
                entry_dt = datetime.fromisoformat(raw_ts)
            except (ValueError, TypeError):
                continue

            compare_dt = (
                entry_dt.replace(tzinfo=None)
                if entry_dt.tzinfo
                else entry_dt
            )

            if start_dt and compare_dt < start_dt:
                continue

            if end_dt:
                end_of_day = end_dt.replace(
                    hour=23,
                    minute=59,
                    second=59,
                )

                if compare_dt > end_of_day:
                    continue

            matched.append(entry)

        return matched

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @staticmethod
    def to_csv(entries: List[dict]) -> str:

        buffer = io.StringIO()

        writer = csv.writer(buffer)

        writer.writerow(
            EXPORT_CSV_COLUMNS + ["extra"]
        )

        for entry in entries:

            if entry.get("_parse_error"):
                writer.writerow(
                    [
                        "",
                        "",
                        "",
                        "UNPARSED_LINE",
                        "",
                        "",
                        "",
                        entry.get("_raw", ""),
                    ]
                )
                continue

            row = [
                entry.get(column, "")
                for column in EXPORT_CSV_COLUMNS
            ]

            extra = {
                key: value
                for key, value in entry.items()
                if key not in EXPORT_CSV_COLUMNS
                and key not in (
                    "_raw",
                    "_parse_error",
                )
            }

            row.append(
                json.dumps(extra)
                if extra
                else ""
            )

            writer.writerow(row)

        return buffer.getvalue()

    @staticmethod
    def to_json(entries: List[dict]) -> str:

        cleaned = []

        for entry in entries:

            if entry.get("_parse_error"):
                cleaned.append(
                    {
                        "_unparsed_line": entry.get(
                            "_raw",
                            "",
                        )
                    }
                )
            else:
                cleaned.append(
                    {
                        key: value
                        for key, value in entry.items()
                        if key != "_raw"
                    }
                )

        return json.dumps(
            cleaned,
            indent=2,
        )


# ----------------------------------------------------------------------
# Shared service instance
# ----------------------------------------------------------------------

audit_log_service = AuditLogService()


# ----------------------------------------------------------------------
# Backward-compatible audit() helper
# ----------------------------------------------------------------------

def audit(
    request,
    action,
    object_name=None,
    old_value=None,
    new_value=None,
    result="SUCCESS",
    error=None,
    *,
    object=None,  # noqa: A002
    details=None,
    **extra,
):
    """
    Backward-compatible wrapper.

    Existing routers can continue calling:

        audit(request, "LOGIN", username, result="FAILED")

    or:

        audit(
            request,
            "CONFIG_CHANGE",
            object="SMTP",
            result="SUCCESS",
            details={...},
        )

    All writes are handled by the shared AuditLogService.
    """

    return audit_log_service.log(
        request,
        action,
        object_name=object_name,
        object=object,
        old_value=old_value,
        new_value=new_value,
        result=result,
        error=error,
        details=details,
        **extra,
    )


# ----------------------------------------------------------------------
# Backward-compatible module-level reader
# ----------------------------------------------------------------------

def read_recent_entries(
    log_path=None,
    limit=200,
):
    """
    Backward-compatible function used by audit/routes.py.

    If a log_path is supplied, use a temporary service instance.
    Otherwise use the shared service.
    """

    service = (
        AuditLogService(log_path)
        if log_path
        else audit_log_service
    )

    return service.read_recent(limit=limit)