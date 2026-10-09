import logging
from typing import Any, Dict, List, Optional, Tuple

import redis


logger = logging.getLogger(__name__)

# Hard caps to keep this a browser, not a full dump tool - a hash/list/set/
# zset with millions of members should never be rendered in one page load.
MAX_COLLECTION_ITEMS = 500
DEFAULT_SCAN_COUNT = 100


class RedisDataError(Exception):
    """Raised for any Redis data read/write failure surfaced to the UI."""


class RedisDataService:
    def __init__(
        self,
        host: str,
        port: int,
        db: int = 0,
        password: Optional[str] = None,
        socket_timeout: float = 3.0,
    ):
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

    def scan_keys(
        self,
        cursor: int = 0,
        pattern: str = "*",
        count: int = DEFAULT_SCAN_COUNT,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        One SCAN iteration (not KEYS *) so browsing a large keyspace never
        blocks the Redis event loop. Returns (next_cursor, entries) where
        next_cursor == 0 means scanning is complete.
        """
        try:
            next_cursor, keys = self._client.scan(
                cursor=cursor, match=pattern or "*", count=count
            )
        except Exception as exc:
            logger.exception("Redis SCAN failed for pattern '%s'", pattern)
            raise RedisDataError(str(exc)) from exc

        entries = []

        for key in keys:
            try:
                key_type = self._client.type(key)
            except Exception:
                logger.warning("Failed to get type for key %s", key, exc_info=True)
                key_type = "unknown"

            try:
                ttl = self._client.ttl(key)
            except Exception:
                logger.warning("Failed to get TTL for key %s", key, exc_info=True)
                ttl = None

            entries.append({"key": key, "type": key_type, "ttl": ttl})

        # Sort for stable, scannable display within a batch. SCAN order
        # itself is not meaningful, so this doesn't lose anything.
        entries.sort(key=lambda e: e["key"])

        return next_cursor, entries

    def get_key_detail(self, key: str) -> Dict[str, Any]:
        """
        Fetches type, TTL, and a rendered value for one key. Collections
        are capped at MAX_COLLECTION_ITEMS with a "truncated" flag rather
        than fetched in full.
        """
        try:
            if not self._client.exists(key):
                raise RedisDataError(f"Key '{key}' does not exist.")

            key_type = self._client.type(key)
            ttl = self._client.ttl(key)
        except RedisDataError:
            raise
        except Exception as exc:
            logger.exception("Failed to inspect key %s", key)
            raise RedisDataError(str(exc)) from exc

        detail: Dict[str, Any] = {
            "key": key,
            "type": key_type,
            "ttl": ttl,
            "truncated": False,
        }

        try:
            if key_type == "string":
                detail["value"] = self._client.get(key)

            elif key_type == "hash":
                total = self._client.hlen(key)
                items = list(self._client.hscan_iter(key))[:MAX_COLLECTION_ITEMS]
                detail["value"] = items
                detail["total"] = total
                detail["truncated"] = total > len(items)

            elif key_type == "list":
                total = self._client.llen(key)
                items = self._client.lrange(key, 0, MAX_COLLECTION_ITEMS - 1)
                detail["value"] = items
                detail["total"] = total
                detail["truncated"] = total > len(items)

            elif key_type == "set":
                total = self._client.scard(key)
                items = list(self._client.sscan_iter(key))[:MAX_COLLECTION_ITEMS]
                detail["value"] = items
                detail["total"] = total
                detail["truncated"] = total > len(items)

            elif key_type == "zset":
                total = self._client.zcard(key)
                items = self._client.zrange(key, 0, MAX_COLLECTION_ITEMS - 1, withscores=True)
                detail["value"] = items
                detail["total"] = total
                detail["truncated"] = total > len(items)

            else:
                detail["value"] = None
                detail["unsupported_type"] = True

        except Exception as exc:
            logger.exception("Failed to read value for key %s (type=%s)", key, key_type)
            raise RedisDataError(str(exc)) from exc

        return detail

    def delete_key(self, key: str) -> bool:
        try:
            if not self._client.exists(key):
                raise RedisDataError(f"Key '{key}' does not exist.")

            deleted = self._client.delete(key)
            return bool(deleted)
        except RedisDataError:
            raise
        except Exception as exc:
            logger.exception("Failed to delete key %s", key)
            raise RedisDataError(str(exc)) from exc