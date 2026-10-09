import logging
from typing import Any, Dict, Optional

import redis


logger = logging.getLogger(__name__)


# Conservative whitelist of Redis runtime parameters considered safe to
# change from a web UI without a special confirmation workflow.
# Deliberately excludes persistence-affecting keys (appendonly, save,
# appendfsync) since those have real durability implications.
EDITABLE_CONFIG_KEYS = {
    "maxmemory": "Maximum memory Redis may use, in bytes. 0 means unlimited.",
    "maxmemory-policy": "Eviction policy applied once maxmemory is reached.",
    "timeout": "Close idle client connections after this many seconds (0 = never).",
    "tcp-keepalive": "TCP keepalive probe interval, in seconds.",
}


class RedisConfigError(Exception):
    """Raised for any Redis configuration read/write failure."""


class RedisConfigService:
    def __init__(
        self,
        host: str,
        port: int,
        db: int = 0,
        password: Optional[str] = None,
        socket_timeout: float = 3.0,
    ):
        self.host = host
        self.port = port
        self.db = db
        self._password_set = bool(password)
        self._client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            socket_timeout=socket_timeout,
            decode_responses=True,
        )

    def connection_info(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "db": self.db,
            "password_configured": self._password_set,
        }

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            logger.exception("Redis ping failed")
            return False

    def server_summary(self) -> Dict[str, Any]:
        """
        A small, curated slice of INFO output for context on this page.
        Not a full status dashboard - that's a separate page's job.
        """
        try:
            info = self._client.info()
        except Exception as exc:
            logger.exception("Failed to fetch Redis INFO")
            raise RedisConfigError(str(exc)) from exc

        return {
            "redis_version": info.get("redis_version"),
            "role": info.get("role"),
            "used_memory_human": info.get("used_memory_human"),
            "connected_clients": info.get("connected_clients"),
            "uptime_in_days": info.get("uptime_in_days"),
        }

    def get_all_config(self) -> Dict[str, str]:
        try:
            config = self._client.config_get("*")
            return dict(sorted(config.items()))
        except Exception as exc:
            logger.exception("Failed to fetch Redis CONFIG GET *")
            raise RedisConfigError(str(exc)) from exc

    def get_editable_config(self) -> Dict[str, Dict[str, str]]:
        """
        Returns {key: {"value": ..., "description": ...}} for only the
        whitelisted, UI-editable keys.
        """
        result = {}

        for key, description in EDITABLE_CONFIG_KEYS.items():
            try:
                current = self._client.config_get(key)
                value = current.get(key, "")
            except Exception:
                logger.exception("Failed to read Redis config key: %s", key)
                value = ""

            result[key] = {"value": value, "description": description}

        return result

    def set_config(self, key: str, value: str) -> Dict[str, str]:
        if key not in EDITABLE_CONFIG_KEYS:
            raise RedisConfigError(f"'{key}' is not an editable configuration key.")

        try:
            current = self._client.config_get(key)
            old_value = current.get(key, "")
        except Exception as exc:
            logger.exception("Failed to read current value for %s before update", key)
            raise RedisConfigError(str(exc)) from exc

        try:
            self._client.config_set(key, value)
        except Exception as exc:
            logger.exception("Failed to set Redis config key %s=%s", key, value)
            raise RedisConfigError(str(exc)) from exc

        return {"key": key, "old_value": old_value, "new_value": value}