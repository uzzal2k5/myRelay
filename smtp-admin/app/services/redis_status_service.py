import logging
import re
from typing import Any, Dict, List, Optional

import redis


logger = logging.getLogger(__name__)


class RedisStatusError(Exception):
    """Raised for any Redis status read failure."""


class RedisStatusService:
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
        self._client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            socket_timeout=socket_timeout,
            decode_responses=True,
        )

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            logger.exception("Redis ping failed")
            return False

    def get_status(self) -> Dict[str, Any]:
        """
        Pulls a curated set of fields across several INFO sections
        (server, memory, clients, stats, replication, keyspace) rather
        than dumping the raw INFO blob - this is a status page, not a
        debug console.
        """
        try:
            info = self._client.info()
        except Exception as exc:
            logger.exception("Failed to fetch Redis INFO for status page")
            raise RedisStatusError(str(exc)) from exc

        keyspace = self._parse_keyspace(info)

        hits = info.get("keyspace_hits", 0)
        misses = info.get("keyspace_misses", 0)
        total_lookups = hits + misses
        hit_rate = round((hits / total_lookups) * 100, 1) if total_lookups else None

        return {
            "connected": True,
            "server": {
                "redis_version": info.get("redis_version"),
                "redis_mode": info.get("redis_mode"),
                "os": info.get("os"),
                "process_id": info.get("process_id"),
                "uptime_in_days": info.get("uptime_in_days"),
                "uptime_in_seconds": info.get("uptime_in_seconds"),
            },
            "memory": {
                "used_memory_human": info.get("used_memory_human"),
                "used_memory_peak_human": info.get("used_memory_peak_human"),
                "used_memory_lua_human": info.get("used_memory_lua_human"),
                "maxmemory_human": info.get("maxmemory_human") or "0B (unlimited)",
                "maxmemory_policy": info.get("maxmemory_policy"),
                "mem_fragmentation_ratio": info.get("mem_fragmentation_ratio"),
            },
            "clients": {
                "connected_clients": info.get("connected_clients"),
                "blocked_clients": info.get("blocked_clients"),
                "tracking_clients": info.get("tracking_clients"),
                "cluster_connections": info.get("cluster_connections"),
            },
            "stats": {
                "total_connections_received": info.get("total_connections_received"),
                "total_commands_processed": info.get("total_commands_processed"),
                "instantaneous_ops_per_sec": info.get("instantaneous_ops_per_sec"),
                "expired_keys": info.get("expired_keys"),
                "evicted_keys": info.get("evicted_keys"),
                "keyspace_hits": hits,
                "keyspace_misses": misses,
                "hit_rate_percent": hit_rate,
            },
            "replication": {
                "role": info.get("role"),
                "connected_slaves": info.get("connected_slaves", 0),
                "master_repl_offset": info.get("master_repl_offset"),
            },
            "persistence": {
                "rdb_last_save_time": info.get("rdb_last_save_time"),
                "rdb_changes_since_last_save": info.get("rdb_changes_since_last_save"),
                "rdb_last_bgsave_status": info.get("rdb_last_bgsave_status"),
                "aof_enabled": bool(info.get("aof_enabled")),
                "aof_last_bgrewrite_status": info.get("aof_last_bgrewrite_status"),
            },
            "keyspace": keyspace,
        }

    @staticmethod
    def _parse_keyspace(info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        redis-py's INFO already parses dbN entries into nested dicts
        under info["dbN"], e.g. {"keys": 12, "expires": 3, "avg_ttl": 0}.
        This normalizes that into a sorted list for template rendering.
        """
        databases = []

        for key, value in info.items():
            match = re.fullmatch(r"db(\d+)", key)
            if not match:
                continue

            databases.append({
                "db": int(match.group(1)),
                "keys": value.get("keys", 0) if isinstance(value, dict) else 0,
                "expires": value.get("expires", 0) if isinstance(value, dict) else 0,
            })

        databases.sort(key=lambda d: d["db"])
        return databases