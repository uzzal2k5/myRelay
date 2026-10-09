import logging
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional


logger = logging.getLogger(__name__)


class RelayhostService:
    """
    Manage Postfix relayhost configuration.

    Example:

        relayhost = [muktopay-com.mail.protection.outlook.com]:25
    """

    RELAYHOST_PATTERN = re.compile(
        r"^\s*\[([^\]]+)\](?::(\d{1,5}))?\s*$"
    )

    HOSTNAME_PATTERN = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9.-]*$"
    )

    def __init__(
        self,
        main_cf_path: str = "/etc/postfix/main.cf",
        backup_path: str = "/etc/postfix/backup",
    ):
        self.main_cf_path = Path(main_cf_path)
        self.backup_path = Path(backup_path)

    # ---------------------------------------------------------
    # Read
    # ---------------------------------------------------------

    def get_relayhost(self) -> Dict:
        """
        Read the currently configured relayhost.

        Uses `postconf` so the value is read exactly as Postfix
        interprets it.
        """

        if not self.main_cf_path.exists():
            raise FileNotFoundError(
                f"Postfix configuration not found: {self.main_cf_path}"
            )

        try:
            result = subprocess.run(
                [
                    "postconf",
                    "-h",
                    "relayhost",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            relayhost = result.stdout.strip()

            if not relayhost:
                return {
                    "configured": False,
                    "raw": "",
                    "endpoint": "",
                    "port": "",
                }

            endpoint, port = self._parse_relayhost(relayhost)

            return {
                "configured": True,
                "raw": relayhost,
                "endpoint": endpoint,
                "port": port,
            }

        except subprocess.CalledProcessError as exc:
            logger.exception("Unable to read Postfix relayhost")

            raise RuntimeError(
                exc.stderr.strip()
                or "Unable to read Postfix relayhost"
            )

    # ---------------------------------------------------------
    # Parse
    # ---------------------------------------------------------

    def _parse_relayhost(self, value: str):
        """
        Parse:

            [hostname]:25

        or:

            [hostname]
        """

        value = value.strip()

        match = self.RELAYHOST_PATTERN.match(value)

        if not match:
            raise ValueError(
                f"Unsupported relayhost format: {value}"
            )

        endpoint = match.group(1)
        port = match.group(2) or ""

        return endpoint, port

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------

    def validate(
        self,
        endpoint: str,
        port: int,
    ) -> None:

        endpoint = endpoint.strip()

        if not endpoint:
            raise ValueError(
                "Relayhost endpoint is required."
            )

        if not self.HOSTNAME_PATTERN.match(endpoint):
            raise ValueError(
                "Invalid relayhost endpoint."
            )

        if "." not in endpoint and endpoint != "localhost":
            raise ValueError(
                "Relayhost endpoint must be a valid hostname or FQDN."
            )

        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ValueError(
                "Relayhost port must be a number."
            )

        if port < 1 or port > 65535:
            raise ValueError(
                "Relayhost port must be between 1 and 65535."
            )

    # ---------------------------------------------------------
    # Build
    # ---------------------------------------------------------

    def build_relayhost(
        self,
        endpoint: str,
        port: int,
    ) -> str:

        self.validate(endpoint, port)

        return f"[{endpoint.strip()}]:{int(port)}"

    # ---------------------------------------------------------
    # Backup
    # ---------------------------------------------------------

    def _create_backup(self) -> Path:

        if not self.main_cf_path.exists():
            raise FileNotFoundError(
                f"Postfix configuration not found: "
                f"{self.main_cf_path}"
            )

        self.backup_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        backup_file = (
            self.backup_path
            / f"main.cf.relayhost.{timestamp}.bak"
        )

        shutil.copy2(
            self.main_cf_path,
            backup_file,
        )

        logger.info(
            "Postfix main.cf backup created: %s",
            backup_file,
        )

        return backup_file

    # ---------------------------------------------------------
    # Update
    # ---------------------------------------------------------

    def update_relayhost(
        self,
        endpoint: str,
        port: int,
    ) -> Dict:

        new_relayhost = self.build_relayhost(
            endpoint,
            port,
        )

        current = self.get_relayhost()

        # No change
        if current["raw"] == new_relayhost:
            return {
                "changed": False,
                "relayhost": new_relayhost,
                "backup": None,
                "message": "Relayhost is already configured with this value.",
            }

        backup_file = self._create_backup()

        try:
            # Update main.cf through Postfix's own configuration tool.
            result = subprocess.run(
                [
                    "postconf",
                    "-e",
                    f"relayhost = {new_relayhost}",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    result.stderr.strip()
                    or "Failed to update relayhost."
                )

            # Validate Postfix configuration.
            check = subprocess.run(
                [
                    "postfix",
                    "check",
                ],
                capture_output=True,
                text=True,
            )

            if check.returncode != 0:
                logger.error(
                    "postfix check failed: %s",
                    check.stderr,
                )

                # Roll back main.cf
                shutil.copy2(
                    backup_file,
                    self.main_cf_path,
                )

                raise RuntimeError(
                    "Postfix configuration validation failed. "
                    "Configuration was rolled back."
                )

            # Reload only after successful validation.
            reload_result = subprocess.run(
                [
                    "postfix",
                    "reload",
                ],
                capture_output=True,
                text=True,
            )

            if reload_result.returncode != 0:

                logger.error(
                    "Postfix reload failed: %s",
                    reload_result.stderr,
                )

                # Restore previous configuration.
                shutil.copy2(
                    backup_file,
                    self.main_cf_path,
                )

                subprocess.run(
                    [
                        "postfix",
                        "reload",
                    ],
                    capture_output=True,
                    text=True,
                )

                raise RuntimeError(
                    "Postfix reload failed. "
                    "Previous configuration was restored."
                )

            logger.info(
                "Relayhost updated successfully: %s",
                new_relayhost,
            )

            return {
                "changed": True,
                "relayhost": new_relayhost,
                "backup": str(backup_file),
                "message": "Relayhost updated successfully.",
            }

        except Exception:
            logger.exception(
                "Failed to update relayhost."
            )
            raise