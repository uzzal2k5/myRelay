import redis
from ..config import settings

class RedisService:
    def __init__(self):
        self.r = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            password=settings.redis_password or None,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )

    def ping(self):
        try:
            return bool(self.r.ping())
        except redis.RedisError:
            return False

    def policy_keys(self):
        # SCAN is used instead of KEYS to avoid blocking Redis.
        return list(self.r.scan_iter(match="smtp:policy:*", count=100))

    def get_policy(self, key):
        if not key.startswith("smtp:policy:"):
            raise ValueError("Invalid policy key")
        return self.r.hgetall(key)

    def set_policy(self, key, values):
        if not key.startswith("smtp:policy:"):
            raise ValueError("Invalid policy key")
        allowed = {"minute", "hour", "day", "week", "month", "year", "status", "source_ip"}
        clean = {k: str(v) for k, v in values.items() if k in allowed}
        if clean:
            self.r.hset(key, mapping=clean)
