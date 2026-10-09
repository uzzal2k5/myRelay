"""
Read-only system readiness checks for the My Relay portal. This
deliberately never installs or modifies anything - it reports what's
missing and, where applicable, the exact command to fix it, consistent
with this app's design rule of not exposing arbitrary shell access.
"""
import importlib.metadata
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import settings


logger = logging.getLogger(__name__)

CHECK_TIMEOUT = 5

REQUIRED_PACKAGES = ["fastapi", "uvicorn", "jinja2", "redis", "ldap3", "pydantic-settings"]

HELPER_SCRIPTS = [
    {"path": "/usr/local/sbin/smtp-admin-postfix-helper", "label": "Postfix helper script"},
    {"path": "/usr/local/sbin/my-relay-policy-ctl", "label": "SMTP policy service control helper"},
]

REQUIRED_UNITS = ["postfix.service", "smtp-policy.service"]


def _item(name: str, status: str, detail: str, fix: Optional[str] = None) -> Dict[str, Any]:
    """status is one of: ok, warn, fail"""
    return {"name": name, "status": status, "detail": detail, "fix": fix}


def _run(args: List[str], timeout: int = CHECK_TIMEOUT) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as exc:
        logger.warning("Installation check command failed: %s (%s)", " ".join(args), exc)
        return None


class InstallationCheckService:
    def get_report(self) -> Dict[str, Any]:
        categories = {
            "Core Services": self._check_core_services(),
            "Privileged Helper Scripts": self._check_helper_scripts(),
            "Active Directory": self._check_ad_config(),
            "Filesystem & Permissions": self._check_filesystem(),
            "Python Environment": self._check_python_packages(),
        }

        all_items = [item for items in categories.values() for item in items]
        return {
            "categories": categories,
            "fail_count": sum(1 for i in all_items if i["status"] == "fail"),
            "warn_count": sum(1 for i in all_items if i["status"] == "warn"),
            "ok_count": sum(1 for i in all_items if i["status"] == "ok"),
        }

    # -----------------------------------------------------------------
    # Core services
    # -----------------------------------------------------------------

    def _check_core_services(self) -> List[Dict[str, Any]]:
        items = []

        # Postfix binary
        if os.path.exists("/usr/sbin/postfix"):
            result = _run(["/usr/sbin/postconf", "-d", "mail_version"])
            version = result.stdout.strip() if result and result.returncode == 0 else "unknown version"
            items.append(_item("Postfix installed", "ok", version))
        else:
            items.append(_item(
                "Postfix installed", "fail", "/usr/sbin/postfix was not found.",
                fix="sudo dnf install postfix",
            ))

        # Required systemd units exist
        for unit in REQUIRED_UNITS:
            result = _run(["systemctl", "cat", unit])
            if result and result.returncode == 0:
                active = _run(["systemctl", "is-active", unit])
                state = active.stdout.strip() if active else "unknown"
                status = "ok" if state == "active" else "warn"
                items.append(_item(f"{unit} unit", status, f"State: {state}"))
            else:
                items.append(_item(
                    f"{unit} unit", "fail", "systemd unit was not found.",
                    fix=f"Confirm the unit file exists, e.g. /etc/systemd/system/{unit}",
                ))

        # Redis reachability
        try:
            from .redis_service import RedisService
            ok = RedisService().ping()
            items.append(_item(
                "Redis reachable", "ok" if ok else "fail",
                f"{settings.redis_host}:{settings.redis_port} db {settings.redis_db}"
                + ("" if ok else " did not respond to PING."),
            ))
        except Exception as exc:
            items.append(_item("Redis reachable", "fail", str(exc)))

        return items

    # -----------------------------------------------------------------
    # Helper scripts + sudoers
    # -----------------------------------------------------------------

    def _check_helper_scripts(self) -> List[Dict[str, Any]]:
        items = []

        for script in HELPER_SCRIPTS:
            path = Path(script["path"])

            if not path.exists():
                items.append(_item(
                    script["label"], "fail", f"{path} does not exist.",
                    fix=f"Install the helper script at {path} (mode 0750, owner root).",
                ))
                continue

            if not os.access(path, os.X_OK):
                items.append(_item(
                    script["label"], "fail", f"{path} exists but is not executable.",
                    fix=f"sudo chmod 0750 {path}",
                ))
                continue

            items.append(_item(script["label"], "ok", f"{path} exists and is executable."))

        # Non-interactive sudo -l check: shows what the CURRENT process's
        # user may run as root without a password. This only reflects
        # reality if the portal's own service account is the one running
        # this check - which it is, since this runs in-process.
        result = _run(["sudo", "-n", "-l"])

        if result is None:
            items.append(_item(
                "sudoers: passwordless helper access", "warn",
                "Could not run 'sudo -n -l' to verify.",
            ))
        elif result.returncode != 0:
            items.append(_item(
                "sudoers: passwordless helper access", "fail",
                "This account cannot use sudo non-interactively at all.",
                fix="Add a NOPASSWD sudoers entry for this service account; see /etc/sudoers.d/.",
            ))
        else:
            output = result.stdout
            missing = [s["path"] for s in HELPER_SCRIPTS if s["path"] not in output]

            if not missing:
                items.append(_item(
                    "sudoers: passwordless helper access", "ok",
                    "This account has NOPASSWD sudo access to the configured helper scripts.",
                ))
            else:
                items.append(_item(
                    "sudoers: passwordless helper access", "fail",
                    f"Missing NOPASSWD sudoers entries for: {', '.join(missing)}",
                    fix="Add entries to /etc/sudoers.d/ for each missing script, e.g.:\n"
                        f"<service_account> ALL=(root) NOPASSWD: {missing[0]}",
                ))

        return items

    # -----------------------------------------------------------------
    # Active Directory configuration completeness
    # -----------------------------------------------------------------

    def _check_ad_config(self) -> List[Dict[str, Any]]:
        items = []

        checks = [
            ("AD server configured", bool(settings.ad_server_1), settings.ad_server_1 or "Not set"),
            ("AD base DN configured", bool(settings.ad_base_dn), settings.ad_base_dn or "Not set"),
            ("AD bind account configured", bool(settings.ad_bind_user), settings.ad_bind_user or "Not set"),
            ("AD bind password configured", bool(settings.ad_bind_password), "Set" if settings.ad_bind_password else "Not set"),
            ("Required access group configured", bool(settings.ad_group_dn), settings.ad_group_dn or "Not set"),
            ("SMTP admin role group configured", bool(settings.role_smtp_admins), settings.role_smtp_admins or "Not set"),
            ("Security admin role group configured", bool(settings.role_security_admins), settings.role_security_admins or "Not set"),
            ("Read-only role group configured", bool(settings.role_read_only), settings.role_read_only or "Not set"),
        ]

        for name, ok, detail in checks:
            items.append(_item(name, "ok" if ok else "fail", detail))

        transport_ok = settings.ad_use_ldaps or settings.ad_use_starttls
        items.append(_item(
            "Encrypted AD connection", "ok" if transport_ok else "warn",
            "LDAPS" if settings.ad_use_ldaps else "StartTLS" if settings.ad_use_starttls else "Plain LDAP (unencrypted)",
        ))

        return items

    # -----------------------------------------------------------------
    # Filesystem & permissions
    # -----------------------------------------------------------------

    def _check_filesystem(self) -> List[Dict[str, Any]]:
        items = []

        paths = [
            ("Postfix backup directory", settings.postfix_backup_path, True),
            ("Audit log directory", str(Path(settings.audit_log_path).parent), True),
            ("Postfix TLS certificate directory", settings.certificate_path, False),
        ]

        for label, raw_path, require_writable in paths:
            path = Path(raw_path)

            if not path.exists():
                items.append(_item(label, "fail", f"{path} does not exist.", fix=f"sudo mkdir -p {path}"))
                continue

            if require_writable and not os.access(path, os.W_OK):
                items.append(_item(
                    label, "fail", f"{path} exists but is not writable by this process.",
                    fix=f"Check ownership/permissions on {path}.",
                ))
                continue

            items.append(_item(label, "ok", f"{path} exists{' and is writable' if require_writable else ''}."))

        return items

    # -----------------------------------------------------------------
    # Python environment
    # -----------------------------------------------------------------

    def _check_python_packages(self) -> List[Dict[str, Any]]:
        items = []

        for package in REQUIRED_PACKAGES:
            try:
                version = importlib.metadata.version(package)
                items.append(_item(package, "ok", f"version {version}"))
            except importlib.metadata.PackageNotFoundError:
                items.append(_item(
                    package, "fail", "Not installed.",
                    fix=f"pip install {package}",
                ))

        return items