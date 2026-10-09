"""
Manages the list of SMTP relay servers this portal is aware of, stored
as a single JSON file. This app has no database, so a small JSON file
(guarded by a file lock-free atomic write) is consistent with how the
rest of this project stores state (the audit log is also a flat file).
"""
import json
import logging
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import settings


logger = logging.getLogger(__name__)

VALID_ENVIRONMENTS = {"production", "staging", "development"}
VALID_ROLES = {"primary_relay", "backup_relay", "outbound_only", "inbound_only", "other"}
CHECK_TIMEOUT = 3


class ServerInventoryError(Exception):
    """Raised for any inventory read/write/validation failure."""


def _inventory_path() -> Path:
    return Path(getattr(settings, "server_inventory_path", "/etc/smtp-admin/server_inventory.json"))


class ServerInventoryService:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or _inventory_path()

    # -----------------------------------------------------------------
    # Storage
    # -----------------------------------------------------------------

    def _read_raw(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []

        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ServerInventoryError(f"Inventory file is not valid JSON: {exc}") from exc
        except Exception as exc:
            raise ServerInventoryError(str(exc)) from exc

        if not isinstance(data, list):
            raise ServerInventoryError("Inventory file must contain a JSON array.")

        return data

    def _write_raw(self, servers: List[Dict[str, Any]]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(servers, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.path)  # atomic on the same filesystem
        except Exception as exc:
            logger.exception("Failed to write server inventory")
            raise ServerInventoryError(str(exc)) from exc

    # -----------------------------------------------------------------
    # CRUD
    # -----------------------------------------------------------------

    def list_servers(self) -> List[Dict[str, Any]]:
        return sorted(self._read_raw(), key=lambda s: s.get("name", "").lower())

    def get_server(self, server_id: str) -> Optional[Dict[str, Any]]:
        for server in self._read_raw():
            if server.get("id") == server_id:
                return server
        return None

    def add_server(
        self,
        name: str,
        hostname: str,
        environment: str,
        role: str,
        port: int = 25,
        notes: str = "",
    ) -> Dict[str, Any]:
        name = (name or "").strip()
        hostname = (hostname or "").strip()
        notes = (notes or "").strip()

        if not name:
            raise ValueError("Server name is required.")
        if not hostname:
            raise ValueError("Hostname or IP is required.")
        if environment not in VALID_ENVIRONMENTS:
            raise ValueError(f"Environment must be one of: {', '.join(sorted(VALID_ENVIRONMENTS))}.")
        if role not in VALID_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(sorted(VALID_ROLES))}.")
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535.")

        servers = self._read_raw()

        if any(s.get("name", "").lower() == name.lower() for s in servers):
            raise ValueError(f"A server named '{name}' already exists.")

        server_id = str(int(time.time() * 1000))
        record = {
            "id": server_id,
            "name": name,
            "hostname": hostname,
            "environment": environment,
            "role": role,
            "port": port,
            "notes": notes,
            "added_at": time.time(),
        }

        servers.append(record)
        self._write_raw(servers)
        return record

    def update_server(self, server_id: str, **fields) -> Dict[str, Any]:
        servers = self._read_raw()

        for i, server in enumerate(servers):
            if server.get("id") == server_id:
                if "environment" in fields and fields["environment"] not in VALID_ENVIRONMENTS:
                    raise ValueError(f"Environment must be one of: {', '.join(sorted(VALID_ENVIRONMENTS))}.")
                if "role" in fields and fields["role"] not in VALID_ROLES:
                    raise ValueError(f"Role must be one of: {', '.join(sorted(VALID_ROLES))}.")

                server.update({k: v for k, v in fields.items() if v is not None})
                self._write_raw(servers)
                return server

        raise ServerInventoryError(f"Server '{server_id}' was not found.")

    def delete_server(self, server_id: str) -> bool:
        servers = self._read_raw()
        remaining = [s for s in servers if s.get("id") != server_id]

        if len(remaining) == len(servers):
            return False

        self._write_raw(remaining)
        return True

    # -----------------------------------------------------------------
    # Reachability
    # -----------------------------------------------------------------

    @staticmethod
    def check_reachability(hostname: str, port: int) -> Dict[str, Any]:
        """
        A plain TCP connect test, not ICMP ping - this app's service
        account won't normally have the raw-socket privilege ping
        requires, and "can we open a connection on the SMTP port" is
        the more relevant question for a mail relay anyway.
        """
        started = time.monotonic()

        try:
            with socket.create_connection((hostname, port), timeout=CHECK_TIMEOUT):
                elapsed_ms = int((time.monotonic() - started) * 1000)
                return {"reachable": True, "elapsed_ms": elapsed_ms, "error": None}
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            return {"reachable": False, "elapsed_ms": elapsed_ms, "error": str(exc)}