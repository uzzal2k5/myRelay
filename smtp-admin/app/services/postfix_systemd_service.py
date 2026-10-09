"""
Full systemd lifecycle control for the Postfix service - start, stop,
restart, enable, disable. Separate from PostfixService (which handles
check/reload/postmap/map editing) because this is a distinct concern:
controlling whether the service runs at all, not validating or editing
its configuration.
"""
import logging
import subprocess

logger = logging.getLogger(__name__)

HELPER = "/usr/local/sbin/smtp-admin-postfix-helper"
UNIT = "postfix.service"
COMMAND_TIMEOUT = 20


class PostfixSystemdError(Exception):
    pass


class PostfixSystemdService:
    def _run(self, args, timeout=COMMAND_TIMEOUT):
        try:
            return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise PostfixSystemdError(f"Command timed out: {' '.join(args)}") from exc
        except Exception as exc:
            raise PostfixSystemdError(str(exc)) from exc

    def get_status(self) -> dict:
        """
        Read-only status check - is-active/is-enabled don't require root,
        so this runs without the helper/sudo, same as dashboard.py's
        existing Postfix check.
        """
        active_result = self._run(["systemctl", "is-active", UNIT])
        enabled_result = self._run(["systemctl", "is-enabled", UNIT])

        return {
            "active": active_result.stdout.strip() or "unknown",
            "enabled": enabled_result.stdout.strip() or "unknown",
        }

    def _privileged_action(self, action: str) -> dict:
        result = self._run(["sudo", HELPER, action])

        if result.returncode != 0:
            raise PostfixSystemdError(result.stderr.strip() or f"{action} failed")

        return self.get_status()

    def start(self) -> dict:
        return self._privileged_action("start")

    def stop(self) -> dict:
        return self._privileged_action("stop")

    def restart(self) -> dict:
        return self._privileged_action("restart")

    def enable(self) -> dict:
        return self._privileged_action("enable")

    def disable(self) -> dict:
        return self._privileged_action("disable")