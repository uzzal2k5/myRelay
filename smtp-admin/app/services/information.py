import os
import socket
import platform
import subprocess
import shutil
import logging
from datetime import datetime


logger = logging.getLogger(__name__)


class InformationService:
    """
    Service class for collecting SMTP server system,
    software, service, memory, disk and runtime information.
    """

    # =========================================================
    # Command Execution
    # =========================================================

    @staticmethod
    def run_command(command: str) -> str:
        """
        Run a system command and return stdout.

        Returns:
            str: Command output or 'N/A' on failure.
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                return result.stdout.strip()

            return "N/A"

        except Exception as exc:
            logger.warning(
                "Command failed [%s]: %s",
                command,
                exc,
            )
            return "N/A"

    # =========================================================
    # Service Status
    # =========================================================

    @staticmethod
    def get_service_status(service: str) -> str:
        """
        Return systemd service status.

        Returns:
            active, inactive, failed, unknown, etc.
        """
        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "is-active",
                    service,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )

            status = result.stdout.strip()

            return status if status else "unknown"

        except Exception as exc:
            logger.warning(
                "Unable to check service [%s]: %s",
                service,
                exc,
            )
            return "unknown"

    # =========================================================
    # Host Information
    # =========================================================

    @staticmethod
    def get_hostname() -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "N/A"

    @staticmethod
    def get_fqdn() -> str:
        try:
            return socket.getfqdn()
        except Exception:
            return "N/A"

    @staticmethod
    def get_ip_address() -> str:
        """
        Return the primary IP address.
        """
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)

        except Exception as exc:
            logger.warning(
                "Unable to determine IP address: %s",
                exc,
            )
            return "N/A"

    # =========================================================
    # Memory
    # =========================================================

    @staticmethod
    def get_memory() -> dict:
        """
        Read memory information from /proc/meminfo.
        """
        try:
            mem = {}

            with open(
                "/proc/meminfo",
                "r",
            ) as f:
                for line in f:
                    key, value = line.split(
                        ":",
                        1,
                    )

                    mem[key] = int(
                        value.strip().split()[0]
                    )

            total = mem.get(
                "MemTotal",
                0,
            )

            available = mem.get(
                "MemAvailable",
                0,
            )

            used = total - available

            percent = (
                round(
                    (used / total) * 100,
                    1,
                )
                if total
                else 0
            )

            return {
                "total": (
                    f"{total / 1024 / 1024:.2f} GB"
                ),
                "used": (
                    f"{used / 1024 / 1024:.2f} GB"
                ),
                "available": (
                    f"{available / 1024 / 1024:.2f} GB"
                ),
                "percent": percent,
            }

        except Exception as exc:
            logger.warning(
                "Unable to read memory information: %s",
                exc,
            )

            return {
                "total": "N/A",
                "used": "N/A",
                "available": "N/A",
                "percent": 0,
            }

    # =========================================================
    # Disk
    # =========================================================

    @staticmethod
    def get_disk(path: str = "/") -> dict:
        """
        Return disk usage for the specified filesystem.
        """
        try:
            usage = shutil.disk_usage(path)

            percent = round(
                (usage.used / usage.total) * 100,
                1,
            )

            return {
                "total": (
                    f"{usage.total / 1024**3:.2f} GB"
                ),
                "used": (
                    f"{usage.used / 1024**3:.2f} GB"
                ),
                "free": (
                    f"{usage.free / 1024**3:.2f} GB"
                ),
                "percent": percent,
            }

        except Exception as exc:
            logger.warning(
                "Unable to read disk information: %s",
                exc,
            )

            return {
                "total": "N/A",
                "used": "N/A",
                "free": "N/A",
                "percent": 0,
            }

    # =========================================================
    # Uptime
    # =========================================================

    @staticmethod
    def get_uptime() -> str:
        """
        Return system uptime.
        """
        try:
            with open(
                "/proc/uptime",
                "r",
            ) as f:
                seconds = float(
                    f.readline().split()[0]
                )

            days = int(
                seconds // 86400
            )

            hours = int(
                (seconds % 86400) // 3600
            )

            minutes = int(
                (seconds % 3600) // 60
            )

            return (
                f"{days}d "
                f"{hours}h "
                f"{minutes}m"
            )

        except Exception as exc:
            logger.warning(
                "Unable to read uptime: %s",
                exc,
            )
            return "N/A"

    # =========================================================
    # Timezone
    # =========================================================

    @classmethod
    def get_timezone(cls) -> str:
        return cls.run_command(
            "timedatectl show "
            "--property=Timezone "
            "--value"
        )

    @staticmethod
    def get_current_time() -> str:
        return datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    # =========================================================
    # Software Versions
    # =========================================================

    @classmethod
    def get_postfix_version(cls) -> str:
        value = cls.run_command(
            "postconf mail_version"
        )

        if value != "N/A":
            value = value.replace(
                "mail_version = ",
                "",
            )

        return value

    @classmethod
    def get_python_version(cls) -> str:
        value = cls.run_command(
            "python3 --version"
        )

        if value != "N/A":
            value = value.replace(
                "Python ",
                "",
            )

        return value

    @classmethod
    def get_redis_version(cls) -> str:
        value = cls.run_command(
            "redis-server --version"
        )

        if value != "N/A":
            if "Redis server v=" in value:
                value = value.split(
                    "Redis server v=",
                    1,
                )[1]

                value = value.split(
                    " ",
                    1,
                )[0]

        return value

    @classmethod
    def get_nginx_version(cls) -> str:
        value = cls.run_command(
            "nginx -v 2>&1"
        )

        if value != "N/A":
            value = value.replace(
                "nginx version: ",
                "",
            )

        return value

    @classmethod
    def get_openssl_version(cls) -> str:
        return cls.run_command(
            "openssl version"
        )

    @classmethod
    def get_software_versions(cls) -> dict:
        return {
            "postfix": cls.get_postfix_version(),
            "python": cls.get_python_version(),
            "redis": cls.get_redis_version(),
            "nginx": cls.get_nginx_version(),
            "openssl": cls.get_openssl_version(),
        }

    # =========================================================
    # Services
    # =========================================================

    @classmethod
    def get_services(cls) -> dict:
        return {
            "postfix": cls.get_service_status(
                "postfix"
            ),
            "nginx": cls.get_service_status(
                "nginx"
            ),
            "redis": cls.get_service_status(
                "redis"
            ),
            "smtp_policy": cls.get_service_status(
                "smtp-policy"
            ),
        }

    # =========================================================
    # System Information
    # =========================================================

    @classmethod
    def get_system_information(cls) -> dict:
        return {
            "hostname": cls.get_hostname(),
            "fqdn": cls.get_fqdn(),
            "ip_address": cls.get_ip_address(),

            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),

            "architecture": platform.machine(),
            "kernel": platform.release(),

            "cpu_count": os.cpu_count(),

            "uptime": cls.get_uptime(),
            "timezone": cls.get_timezone(),
            "current_time": cls.get_current_time(),
        }

    # =========================================================
    # Complete Information
    # =========================================================

    @classmethod
    def get_information(cls) -> dict:
        """
        Return complete SMTP server information.
        """

        return {
            "system": cls.get_system_information(),
            "software": cls.get_software_versions(),
            "services": cls.get_services(),
            "memory": cls.get_memory(),
            "disk": cls.get_disk(),
        }

