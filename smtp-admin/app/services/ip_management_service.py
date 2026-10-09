import ipaddress
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


logger = logging.getLogger(__name__)


class IPManagementService:
    """
    Manage Postfix IP policy files.

    Files:

        allowed_ips
        denied_ips
        blocked_ips

    The service manages only IP/network policy lines and preserves
    comments/blank lines that may already exist in the files.
    """

    POLICY_CONFIG = {
        "allowed": {
            "file": "/etc/postfix/ip-management/allowed_ips",
            "action": "OK",
            "message": "",
        },
        "denied": {
            "file": "/etc/postfix/ip-management/denied_ips",
            "action": "REJECT",
            "message": "Access denied",
        },
        "blocked": {
            "file": "/etc/postfix/ip-management/blocked_ips",
            "action": "REJECT",
            "message": "Blocked",
        },
    }

    IP_LINE_PREFIXES = {
        "allowed": "OK",
        "denied": "REJECT",
        "blocked": "REJECT",
    }

    def __init__(
        self,
        backup_path: str = "/etc/postfix/backup",
    ):
        self.backup_path = Path(backup_path)

    # =========================================================
    # Policy configuration
    # =========================================================

    def _get_policy(self, policy: str) -> Dict:
        if policy not in self.POLICY_CONFIG:
            raise ValueError(
                f"Unsupported IP policy: {policy}"
            )

        return self.POLICY_CONFIG[policy]

    # =========================================================
    # File path
    # =========================================================

    def get_file_path(self, policy: str) -> Path:
        config = self._get_policy(policy)
        return Path(config["file"])

    # =========================================================
    # Validate IP / Network
    # =========================================================

    def validate_address(
        self,
        value: str,
    ) -> str:
        """
        Validate an IP address or CIDR network.

        Examples:

            172.17.65.36
            10.10.20.0/24
            2001:db8::10
            2001:db8::/64
        """

        value = value.strip()

        if not value:
            raise ValueError(
                "IP address or network cannot be empty."
            )

        try:
            if "/" in value:
                network = ipaddress.ip_network(
                    value,
                    strict=False,
                )

                return str(network)

            address = ipaddress.ip_address(value)

            return str(address)

        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address or network: {value}"
            ) from exc

    # =========================================================
    # Parse policy line
    # =========================================================

    def _parse_policy_line(
        self,
        policy: str,
        line: str,
    ) -> Tuple[str, str]:
        """
        Parse a Postfix policy line.

        Returns:

            address, complete_line

        Example:

            172.17.65.36    OK

        returns:

            ("172.17.65.36", "172.17.65.36    OK")
        """

        stripped = line.strip()

        if not stripped:
            return "", ""

        if stripped.startswith("#"):
            return "", ""

        parts = stripped.split(None, 1)

        if len(parts) < 2:
            return "", ""

        address = parts[0]
        action = parts[1]

        try:
            address = self.validate_address(address)
        except ValueError:
            return "", ""

        expected_action = self._get_policy(policy)["action"]

        if not action.startswith(expected_action):
            return "", ""

        return address, stripped

    # =========================================================
    # Read policy
    # =========================================================

    def get_policy_entries(
        self,
        policy: str,
    ) -> List[Dict]:
        """
        Return configured entries for a policy.
        """

        path = self.get_file_path(policy)

        if not path.exists():
            return []

        entries = []
        seen = set()

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:
                address, raw_line = self._parse_policy_line(
                    policy,
                    line,
                )

                if not address:
                    continue

                if address in seen:
                    continue

                seen.add(address)

                entries.append(
                    {
                        "address": address,
                        "line": raw_line,
                    }
                )

        return sorted(
            entries,
            key=lambda item: item["address"],
        )

    # =========================================================
    # Get all policies
    # =========================================================

    def get_all_policies(self) -> Dict:
        return {
            "allowed": self.get_policy_entries(
                "allowed"
            ),
            "denied": self.get_policy_entries(
                "denied"
            ),
            "blocked": self.get_policy_entries(
                "blocked"
            ),
        }

    # =========================================================
    # Backup
    # =========================================================

    def _backup_file(
        self,
        path: Path,
    ) -> Path:

        self.backup_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        backup_file = (
            self.backup_path
            / f"{path.name}.{timestamp}.bak"
        )

        if path.exists():
            shutil.copy2(
                path,
                backup_file,
            )
        else:
            backup_file.touch()

        logger.info(
            "IP policy backup created: %s",
            backup_file,
        )

        return backup_file

    # =========================================================
    # Build policy line
    # =========================================================

    def _build_line(
        self,
        policy: str,
        address: str,
    ) -> str:

        config = self._get_policy(policy)

        if policy == "allowed":
            return f"{address}    OK"

        if policy == "denied":
            return (
                f"{address}    REJECT Access denied"
            )

        if policy == "blocked":

            if "/" in address:
                return (
                    f"{address}    REJECT Blocked network"
                )

            return (
                f"{address}    REJECT Blocked IP"
            )

        raise ValueError(
            f"Unsupported policy: {policy}"
        )

    # =========================================================
    # Apply desired configuration
    # =========================================================

    def apply_policy(
        self,
        policy: str,
        addresses: List[str],
    ) -> Dict:

        path = self.get_file_path(policy)

        # -----------------------------------------------------
        # Validate and normalize
        # -----------------------------------------------------

        normalized = []

        for value in addresses:
            value = value.strip()

            if not value:
                continue

            address = self.validate_address(value)

            if address not in normalized:
                normalized.append(address)

        normalized.sort()

        # -----------------------------------------------------
        # Existing configuration
        # -----------------------------------------------------

        existing_entries = self.get_policy_entries(
            policy
        )

        existing = {
            entry["address"]
            for entry in existing_entries
        }

        desired = set(normalized)

        added = sorted(
            desired - existing
        )

        removed = sorted(
            existing - desired
        )

        unchanged = sorted(
            existing & desired
        )

        # -----------------------------------------------------
        # Nothing changed
        # -----------------------------------------------------

        if not added and not removed:
            return {
                "changed": False,
                "policy": policy,
                "file": str(path),
                "added": [],
                "removed": [],
                "unchanged": unchanged,
                "message": (
                    f"No changes required for "
                    f"{policy} IP policy."
                ),
            }

        # -----------------------------------------------------
        # Backup
        # -----------------------------------------------------

        backup_file = self._backup_file(path)

        try:

            # -------------------------------------------------
            # Preserve comments and unrelated lines.
            # -------------------------------------------------

            preserved_lines = []

            if path.exists():

                with path.open(
                    "r",
                    encoding="utf-8",
                ) as file:

                    for line in file:

                        stripped = line.strip()

                        # Keep blank lines
                        if not stripped:
                            preserved_lines.append(
                                line.rstrip("\n")
                            )
                            continue

                        # Keep comments
                        if stripped.startswith("#"):
                            preserved_lines.append(
                                line.rstrip("\n")
                            )
                            continue

                        address, _ = (
                            self._parse_policy_line(
                                policy,
                                line,
                            )
                        )

                        # Preserve lines that don't belong to
                        # this managed policy format.
                        if not address:
                            preserved_lines.append(
                                line.rstrip("\n")
                            )

            # -------------------------------------------------
            # Build managed policy entries
            # -------------------------------------------------

            managed_lines = [
                self._build_line(
                    policy,
                    address,
                )
                for address in normalized
            ]

            # -------------------------------------------------
            # Atomic temporary file
            # -------------------------------------------------

            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            temp_path = path.with_suffix(
                path.suffix + ".tmp"
            )

            with temp_path.open(
                "w",
                encoding="utf-8",
            ) as file:

                for line in preserved_lines:
                    file.write(
                        line.rstrip("\n")
                        + "\n"
                    )

                for line in managed_lines:
                    file.write(
                        line
                        + "\n"
                    )

                file.flush()
                os.fsync(file.fileno())

            # Preserve ownership and permissions where possible.
            if path.exists():

                stat = path.stat()

                os.chmod(
                    temp_path,
                    stat.st_mode,
                )

                try:
                    os.chown(
                        temp_path,
                        stat.st_uid,
                        stat.st_gid,
                    )
                except PermissionError:
                    logger.warning(
                        "Unable to preserve ownership "
                        "for %s",
                        path,
                    )

            os.replace(
                temp_path,
                path,
            )

            logger.info(
                "IP policy updated: policy=%s file=%s "
                "added=%s removed=%s",
                policy,
                path,
                added,
                removed,
            )

            return {
                "changed": True,
                "policy": policy,
                "file": str(path),
                "backup": str(backup_file),
                "added": added,
                "removed": removed,
                "unchanged": unchanged,
                "message": (
                    f"{policy.title()} IP policy updated "
                    f"successfully."
                ),
            }

        except Exception:

            logger.exception(
                "Failed to update IP policy: %s",
                policy,
            )

            # Restore previous file.
            if backup_file.exists():

                shutil.copy2(
                    backup_file,
                    path,
                )

            raise