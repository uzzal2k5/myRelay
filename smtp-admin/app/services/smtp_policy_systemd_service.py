import subprocess


class SmtpPolicySystemdService:
    HELPER = "/usr/local/sbin/my-relay-policy-ctl"

    ALLOWED_ACTIONS = {
        "status",
        "enabled",
        "start",
        "stop",
        "restart",
        "enable",
    }

    def _run(self, action: str) -> str:
        if action not in self.ALLOWED_ACTIONS:
            raise ValueError("Unsupported service action")

        result = subprocess.run(
            ["sudo", "-n", self.HELPER, action],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if result.returncode != 0:
            message = (
                result.stderr.strip()
                or result.stdout.strip()
                or "Systemd operation failed"
            )
            raise RuntimeError(message)

        return result.stdout.strip()

    def get_status(self):
        return {
            "service": "smtp-policy.service",
            "active": self._run("status"),
            "enabled": self._run("enabled"),
        }

    def start(self):
        self._run("start")
        return self.get_status()

    def stop(self):
        self._run("stop")
        return self.get_status()

    def restart(self):
        self._run("restart")
        return self.get_status()

    def enable(self):
        self._run("enable")
        return self.get_status()