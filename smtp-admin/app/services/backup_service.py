"""
Lists, restores, and prunes the timestamped backups PostfixService
already creates (see PostfixService.backup()) before every map edit.
This does not duplicate that write/validate/reload logic - restoring a
backup is implemented as "write the old content back through the same
PostfixService.write_existing_map() path used for every other map
edit," so a restore gets the exact same backup-before-write, postmap,
postfix check, and automatic rollback-on-failure guarantees as a normal
save, rather than a parallel, less-tested code path.
"""
import logging
import re
import shutil
import difflib
from pathlib import Path
from typing import Any, Dict, List, Optional

from .postfix_service import PostfixService


logger = logging.getLogger(__name__)

# Matches PostfixService.backup()'s naming: "<original_name>.<YYYYMMDD-HHMMSS>.bak"
BACKUP_NAME_RE = re.compile(r"^(?P<original>.+)\.(?P<timestamp>\d{8}-\d{6})\.bak$")


class BackupServiceError(Exception):
    pass


class BackupService:
    def __init__(self, postfix_service: Optional[PostfixService] = None):
        self.postfix_service = postfix_service or PostfixService()
        self.backup_directory = self.postfix_service.backup_directory

    # -----------------------------------------------------------------
    # Listing
    # -----------------------------------------------------------------

    def list_backups(self) -> List[Dict[str, Any]]:
        if not self.backup_directory.exists():
            return []

        configured_maps = self.postfix_service.discover_existing_maps()
        configured_names = {Path(info["path"]).name for info in configured_maps.values()}

        results = []

        for entry in self.backup_directory.iterdir():
            if not entry.is_file():
                continue

            match = BACKUP_NAME_RE.match(entry.name)
            if not match:
                # A file in the backup directory that doesn't match the
                # naming convention (e.g. a cert backup, or something
                # placed there manually). Still shown, but restore is
                # not offered for it - see is_restorable below.
                original_name = None
                timestamp = None
            else:
                original_name = match.group("original")
                timestamp = match.group("timestamp")

            try:
                stat = entry.stat()
            except OSError:
                continue

            results.append({
                "filename": entry.name,
                "original_name": original_name,
                "timestamp": timestamp,
                "size_bytes": stat.st_size,
                "modified_at": stat.st_mtime,
                "is_restorable": original_name is not None and original_name in configured_names,
                "is_configured_map": original_name is not None and original_name in configured_names,
            })

        results.sort(key=lambda b: b["modified_at"], reverse=True)
        return results

    def total_size_bytes(self, backups: Optional[List[Dict[str, Any]]] = None) -> int:
        backups = backups if backups is not None else self.list_backups()
        return sum(b["size_bytes"] for b in backups)

    # -----------------------------------------------------------------
    # Path safety
    # -----------------------------------------------------------------

    def _resolve_backup_path(self, filename: str) -> Path:
        if not filename or "/" in filename or filename in (".", ".."):
            raise ValueError("Invalid backup filename.")

        resolved = (self.backup_directory / filename).resolve()

        if self.backup_directory.resolve() not in resolved.parents:
            raise ValueError("Backup path is outside the backup directory.")

        if not resolved.is_file():
            raise BackupServiceError(f"Backup file not found: {filename}")

        return resolved

    # -----------------------------------------------------------------
    # Restore
    # -----------------------------------------------------------------

    def restore_backup(self, filename: str) -> Dict[str, Any]:
        """
        Restores one backup's content over its live map file. Only
        permitted for backups whose original filename matches a map
        Postfix is actually currently configured to use - restoring
        into an unconfigured or unrecognized path is refused, the same
        restriction write_existing_map() already applies to direct edits.
        """
        backup_path = self._resolve_backup_path(filename)
        match = BACKUP_NAME_RE.match(filename)

        if not match:
            raise ValueError(
                "This file does not follow the standard backup naming pattern "
                "and cannot be restored automatically."
            )

        original_name = match.group("original")
        configured_maps = self.postfix_service.discover_existing_maps()

        target_info = next(
            (info for info in configured_maps.values() if Path(info["path"]).name == original_name),
            None,
        )

        if not target_info:
            raise ValueError(
                f"'{original_name}' is not currently referenced by the active "
                "Postfix configuration, so it cannot be restored."
            )

        target_path = target_info["path"]

        try:
            lines = backup_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as exc:
            raise BackupServiceError(f"Could not read backup file: {exc}") from exc

        # write_existing_map() backs up the CURRENT live file before
        # overwriting it, validates with postmap/postfix check, reloads,
        # and automatically rolls back on any failure - so a restore
        # that turns out to be bad is itself always undoable.
        result = self.postfix_service.write_existing_map(target_path, lines)
        result["restored_from"] = filename
        result["restored_at"] = original_name
        return result

    # -----------------------------------------------------------------
    # Manual backup trigger
    # -----------------------------------------------------------------

    def create_backup_now(self, map_path: str) -> Path:
        backup_path = self.postfix_service.backup(map_path)

        if backup_path is None:
            raise BackupServiceError(f"Source file does not exist: {map_path}")

        return backup_path


    #-----------------------------------------------------------------
    # pick a backup → preview a diff against the live file → confirm → restore
    # -----------------------------------------------------------------

    def preview_restore(self, filename: str) -> Dict[str, Any]:
        """
        Builds a diff between a backup's content and the current live
        content of the map it would restore into - read-only, nothing
        is written. Used by the preview step before a restore is
        confirmed.
        """
        backup_path = self._resolve_backup_path(filename)
        match = BACKUP_NAME_RE.match(filename)

        if not match:
            raise ValueError(
                "This file does not follow the standard backup naming pattern "
                "and cannot be restored automatically."
            )

        original_name = match.group("original")
        configured_maps = self.postfix_service.discover_existing_maps()

        target_info = next(
            (info for info in configured_maps.values() if Path(info["path"]).name == original_name),
            None,
        )

        if not target_info:
            raise ValueError(
                f"'{original_name}' is not currently referenced by the active "
                "Postfix configuration, so it cannot be restored."
            )

        target_path = Path(target_info["path"])

        try:
            backup_lines = backup_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as exc:
            raise BackupServiceError(f"Could not read backup file: {exc}") from exc

        try:
            current_lines = (
                target_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if target_path.exists() else []
            )
        except Exception as exc:
            raise BackupServiceError(f"Could not read current live file: {exc}") from exc

        diff_lines = list(difflib.unified_diff(
            current_lines, backup_lines,
            fromfile=f"current/{original_name}",
            tofile=f"backup/{filename}",
            lineterm="",
        ))

        added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))

        return {
            "filename": filename,
            "original_name": original_name,
            "target_path": str(target_path),
            "diff_lines": diff_lines,
            "added": added,
            "removed": removed,
            "identical": added == 0 and removed == 0,
            "current_line_count": len(current_lines),
            "backup_line_count": len(backup_lines),
        }
    # -----------------------------------------------------------------
    # Cleanup
    # -----------------------------------------------------------------

    def delete_backup(self, filename: str) -> None:
        backup_path = self._resolve_backup_path(filename)

        try:
            backup_path.unlink()
        except Exception as exc:
            raise BackupServiceError(f"Could not delete backup: {exc}") from exc