"""
Aggregates health checks across every subsystem this portal manages into
one status snapshot, for the /monitoring ("System Status") page. Each
check is independent and failure-isolated - one subsystem being down
must never prevent the others from reporting correctly.
"""
import logging
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from ..config import settings
from .redis_service import RedisService
from .smtp_policy_systemd_service import SmtpPolicySystemdService


logger = logging.getLogger(__name__)

CHECK_TIMEOUT = 5

# Paths worth watching for disk pressure - the mail spool/queue directory
# and the audit/application log path are the two most likely to fill up
# an otherwise-healthy host.
DISK_PATHS = {
    "Postfix spool (/var/spool/postfix)": "/var/spool/postfix",
    "Postfix config (/etc/postfix)": "/etc/postfix",
    "Audit log volume": "/var/log/smtp-admin",
}

DISK_WARN_PERCENT = 80
DISK_CRITICAL_PERCENT = 90


def _run(args: List[str], timeout: int = CHECK_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


class SystemStatusService:
    def get_snapshot(self) -> Dict[str, Any]:
        return {
            "generated_at": time.time(),
            "services": self._check_services(),
            "host": self._check_host(),
            "disks": self._check_disks(),
        }

    # -----------------------------------------------------------------
    # Service checks
    # -----------------------------------------------------------------

    def _check_services(self) -> List[Dict[str, Any]]:
        return [
            self._check_postfix(),
            self._check_redis(),
            self._check_smtp_policy(),
            self._check_ldap(),
        ]

    @staticmethod
    def _check_postfix() -> Dict[str, Any]:
        try:
            result = _run(["systemctl", "is-active", "postfix"])
            active = result.stdout.strip()
            ok = result.returncode == 0 and active == "active"
            return {
                "name": "Postfix",
                "icon": "bi-envelope-paper-fill",
                "ok": ok,
                "state": active or "unknown",
                "detail": None if ok else (result.stderr.strip() or "Service is not active."),
                "link": "/postfix",
            }
        except Exception as exc:
            logger.exception("System status: Postfix check failed")
            return {
                "name": "Postfix", "icon": "bi-envelope-paper-fill", "ok": False,
                "state": "unknown", "detail": str(exc), "link": "/postfix",
            }

    @staticmethod
    def _check_redis() -> Dict[str, Any]:
        try:
            ok = RedisService().ping()
            return {
                "name": "Redis",
                "icon": "bi-database-fill",
                "ok": ok,
                "state": "up" if ok else "down",
                "detail": None if ok else "Redis did not respond to PING.",
                "link": "/redis/status",
            }
        except Exception as exc:
            logger.exception("System status: Redis check failed")
            return {
                "name": "Redis", "icon": "bi-database-fill", "ok": False,
                "state": "down", "detail": str(exc), "link": "/redis/status",
            }

    @staticmethod
    def _check_smtp_policy() -> Dict[str, Any]:
        try:
            status = SmtpPolicySystemdService().get_status()
            active = status.get("active", "unknown")
            ok = active == "active"
            return {
                "name": "SMTP Policy Service",
                "icon": "bi-shield-check",
                "ok": ok,
                "state": active,
                "detail": None if ok else "The policy service is not active.",
                "link": "/smtp/policy",
            }
        except Exception as exc:
            logger.exception("System status: SMTP policy service check failed")
            return {
                "name": "SMTP Policy Service", "icon": "bi-shield-check", "ok": False,
                "state": "unknown", "detail": str(exc), "link": "/smtp/policy",
            }

    @staticmethod
    def _check_ldap() -> Dict[str, Any]:
        """
        A lightweight reachability check only - opens a connection to the
        first configured DC and confirms a bind succeeds. This deliberately
        does not reuse LdapConfigService.test_connection()'s full 3-step
        report (connect/bind/read-base-DN); that level of detail belongs
        on the dedicated /ldap page, not a one-line summary tile here.
        """
        try:
            from ldap3 import Connection, Server, Tls
            import ssl

            host = settings.ad_server_1
            if not host:
                return {
                    "name": "LDAP / Active Directory", "icon": "bi-diagram-3", "ok": False,
                    "state": "unconfigured", "detail": "No AD server configured.", "link": "/ldap",
                }

            tls = None
            if settings.ad_use_ldaps or settings.ad_use_starttls:
                tls = Tls(
                    validate=ssl.CERT_REQUIRED if settings.ad_verify_cert else ssl.CERT_NONE,
                    ca_certs_file=settings.ad_ca_certs_file or None,
                )

            server = Server(
                host, port=settings.ad_ldap_port, use_ssl=settings.ad_use_ldaps,
                tls=tls, connect_timeout=CHECK_TIMEOUT,
            )
            conn = Connection(
                server, user=settings.ad_bind_user, password=settings.ad_bind_password,
                auto_bind=False, raise_exceptions=False, receive_timeout=CHECK_TIMEOUT,
            )
            conn.open()

            if settings.ad_use_starttls and not settings.ad_use_ldaps:
                conn.start_tls()

            ok = conn.bind()
            detail = None if ok else str(conn.result.get("description", "bind failed"))
            conn.unbind()

            return {
                "name": "LDAP / Active Directory", "icon": "bi-diagram-3", "ok": ok,
                "state": "reachable" if ok else "unreachable", "detail": detail, "link": "/ldap",
            }
        except Exception as exc:
            logger.exception("System status: LDAP check failed")
            return {
                "name": "LDAP / Active Directory", "icon": "bi-diagram-3", "ok": False,
                "state": "unreachable", "detail": str(exc), "link": "/ldap",
            }

    # -----------------------------------------------------------------
    # Host-level checks
    # -----------------------------------------------------------------

    @staticmethod
    def _check_host() -> Dict[str, Any]:
        try:
            import os
            load1, load5, load15 = os.getloadavg()
            cpu_count = os.cpu_count() or 1

            uptime_seconds = None
            try:
                with open("/proc/uptime") as f:
                    uptime_seconds = float(f.read().split()[0])
            except Exception:
                pass

            mem_total_kb = mem_available_kb = None
            try:
                with open("/proc/meminfo") as f:
                    meminfo = {}
                    for line in f:
                        key, _, rest = line.partition(":")
                        meminfo[key.strip()] = rest.strip().split()[0]
                mem_total_kb = int(meminfo.get("MemTotal", 0))
                mem_available_kb = int(meminfo.get("MemAvailable", 0))
            except Exception:
                pass

            mem_used_percent = None
            if mem_total_kb and mem_available_kb is not None:
                mem_used_percent = round((1 - mem_available_kb / mem_total_kb) * 100, 1)

            return {
                "load1": round(load1, 2),
                "load5": round(load5, 2),
                "load15": round(load15, 2),
                "cpu_count": cpu_count,
                "load_per_cpu": round(load1 / cpu_count, 2) if cpu_count else None,
                "uptime_days": round(uptime_seconds / 86400, 1) if uptime_seconds else None,
                "mem_used_percent": mem_used_percent,
                "mem_total_gb": round(mem_total_kb / (1024 * 1024), 1) if mem_total_kb else None,
            }
        except Exception as exc:
            logger.exception("System status: host resource check failed")
            return {"error": str(exc)}

    @staticmethod
    def _check_disks() -> List[Dict[str, Any]]:
        results = []

        for label, path in DISK_PATHS.items():
            try:
                usage = shutil.disk_usage(path)
                percent = round((usage.used / usage.total) * 100, 1)

                if percent >= DISK_CRITICAL_PERCENT:
                    level = "critical"
                elif percent >= DISK_WARN_PERCENT:
                    level = "warn"
                else:
                    level = "ok"

                results.append({
                    "label": label,
                    "path": path,
                    "percent": percent,
                    "used_gb": round(usage.used / (1024 ** 3), 1),
                    "total_gb": round(usage.total / (1024 ** 3), 1),
                    "level": level,
                    "error": None,
                })
            except FileNotFoundError:
                results.append({
                    "label": label, "path": path, "percent": None, "used_gb": None,
                    "total_gb": None, "level": "unknown", "error": "Path does not exist.",
                })
            except Exception as exc:
                logger.warning("Disk check failed for %s", path, exc_info=True)
                results.append({
                    "label": label, "path": path, "percent": None, "used_gb": None,
                    "total_gb": None, "level": "unknown", "error": str(exc),
                })

        return results