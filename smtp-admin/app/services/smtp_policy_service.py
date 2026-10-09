#!/usr/bin/env python3

import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import redis


logger = logging.getLogger("my-relay.smtp-policy")


class SmtpPolicyService:

    REDIS_HOST = "127.0.0.1"
    REDIS_PORT = 6379
    REDIS_DB = 1

    TIMEZONE = ZoneInfo("Asia/Dhaka")

    DEFAULT_MINUTE_LIMIT = 10
    DEFAULT_HOUR_LIMIT = 100
    DEFAULT_DAY_LIMIT = 500

    MAX_MINUTE_LIMIT = 100000
    MAX_HOUR_LIMIT = 1000000
    MAX_DAY_LIMIT = 10000000

    RATE_LIMIT_SCRIPT = r"""
    local minute_key = KEYS[1]
    local hour_key   = KEYS[2]
    local day_key    = KEYS[3]

    local minute_limit = tonumber(ARGV[1])
    local hour_limit   = tonumber(ARGV[2])
    local day_limit    = tonumber(ARGV[3])

    local minute_ttl = tonumber(ARGV[4])
    local hour_ttl   = tonumber(ARGV[5])
    local day_ttl    = tonumber(ARGV[6])

    local minute_count = tonumber(redis.call("GET", minute_key) or "0")
    local hour_count   = tonumber(redis.call("GET", hour_key) or "0")
    local day_count    = tonumber(redis.call("GET", day_key) or "0")

    -- Check before increment.
    if minute_count >= minute_limit then
        return 1
    end

    if hour_count >= hour_limit then
        return 2
    end

    if day_count >= day_limit then
        return 3
    end

    -- Atomic increment.
    local new_minute = redis.call("INCR", minute_key)
    local new_hour   = redis.call("INCR", hour_key)
    local new_day    = redis.call("INCR", day_key)

    -- Set TTL only when key is first created.
    if new_minute == 1 then
        redis.call("EXPIRE", minute_key, minute_ttl)
    end

    if new_hour == 1 then
        redis.call("EXPIRE", hour_key, hour_ttl)
    end

    if new_day == 1 then
        redis.call("EXPIRE", day_key, day_ttl)
    end

    return 0
    """

    def __init__(self):
        self.redis = redis.Redis(
            host=self.REDIS_HOST,
            port=self.REDIS_PORT,
            db=self.REDIS_DB,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
            health_check_interval=30,
        )

        self.rate_limit_script = self.redis.register_script(
            self.RATE_LIMIT_SCRIPT
        )

    # =========================================================
    # Redis
    # =========================================================

    def ping(self) -> bool:
        try:
            return bool(self.redis.ping())
        except Exception:
            logger.exception("Redis ping failed")
            return False

    # =========================================================
    # Username
    # =========================================================

    @staticmethod
    def clean_username(username: str) -> str:
        return (username or "").strip().lower()

    @staticmethod
    def validate_username(username: str) -> str:
        username = SmtpPolicyService.clean_username(username)

        if not username:
            raise ValueError("SMTP username is required")

        if len(username) > 320:
            raise ValueError("SMTP username is too long")

        if "@" not in username:
            raise ValueError(
                "SMTP username must be a valid email address"
            )

        local, domain = username.rsplit("@", 1)

        if not local:
            raise ValueError("SMTP username local part is empty")

        if not domain:
            raise ValueError("SMTP username domain is empty")

        if any(ch.isspace() for ch in username):
            raise ValueError(
                "SMTP username must not contain whitespace"
            )

        return username

    # =========================================================
    # Policy validation
    # =========================================================

    @staticmethod
    def validate_limit(
        value,
        name: str,
        maximum: int,
    ) -> int:

        try:
            value = int(value)
        except (TypeError, ValueError):
            raise ValueError(
                f"{name} must be a valid integer"
            )

        if value < 1:
            raise ValueError(
                f"{name} must be greater than zero"
            )

        if value > maximum:
            raise ValueError(
                f"{name} must not exceed {maximum}"
            )

        return value

    def validate_configuration(
        self,
        username: str,
        enabled,
        minute_limit,
        hour_limit,
        day_limit,
    ):

        username = self.validate_username(username)

        minute_limit = self.validate_limit(
            minute_limit,
            "Minute limit",
            self.MAX_MINUTE_LIMIT,
        )

        hour_limit = self.validate_limit(
            hour_limit,
            "Hour limit",
            self.MAX_HOUR_LIMIT,
        )

        day_limit = self.validate_limit(
            day_limit,
            "Day limit",
            self.MAX_DAY_LIMIT,
        )

        if minute_limit > hour_limit:
            raise ValueError(
                "Minute limit cannot be greater than hour limit"
            )

        if hour_limit > day_limit:
            raise ValueError(
                "Hour limit cannot be greater than day limit"
            )

        return {
            "username": username,
            "enabled": bool(enabled),
            "minute_limit": minute_limit,
            "hour_limit": hour_limit,
            "day_limit": day_limit,
        }

    # =========================================================
    # User configuration
    # =========================================================

    def get_user_config(self, username: str):

        username = self.clean_username(username)

        if not username:
            return None

        key = f"smtp:user:{username}"

        data = self.redis.hgetall(key)

        if not data:
            return None

        try:
            minute_limit = int(
                data.get(
                    "minute_limit",
                    self.DEFAULT_MINUTE_LIMIT,
                )
            )

            hour_limit = int(
                data.get(
                    "hour_limit",
                    self.DEFAULT_HOUR_LIMIT,
                )
            )

            day_limit = int(
                data.get(
                    "day_limit",
                    self.DEFAULT_DAY_LIMIT,
                )
            )

        except ValueError:

            logger.error(
                "Invalid Redis policy configuration user=%s",
                username,
            )

            return None

        return {
            "username": username,
            "enabled": data.get("enabled", "0") == "1",
            "minute_limit": minute_limit,
            "hour_limit": hour_limit,
            "day_limit": day_limit,
        }

    def save_user_config(
        self,
        username: str,
        enabled,
        minute_limit,
        hour_limit,
        day_limit,
    ):

        config = self.validate_configuration(
            username=username,
            enabled=enabled,
            minute_limit=minute_limit,
            hour_limit=hour_limit,
            day_limit=day_limit,
        )

        username = config["username"]

        key = f"smtp:user:{username}"

        self.redis.hset(
            key,
            mapping={
                "enabled": (
                    "1"
                    if config["enabled"]
                    else "0"
                ),
                "minute_limit": config["minute_limit"],
                "hour_limit": config["hour_limit"],
                "day_limit": config["day_limit"],
            },
        )

        logger.info(
            "POLICY_CONFIG_UPDATE "
            "user=%s enabled=%s minute=%s hour=%s day=%s",
            username,
            config["enabled"],
            config["minute_limit"],
            config["hour_limit"],
            config["day_limit"],
        )

        return config

    def delete_user(self, username: str):

        username = self.validate_username(username)

        key = f"smtp:user:{username}"

        result = self.redis.delete(key)

        logger.warning(
            "POLICY_CONFIG_DELETE user=%s deleted=%s",
            username,
            result,
        )

        return result > 0

    def list_users(self):

        users = []

        for key in self.redis.scan_iter(
            match="smtp:user:*",
            count=100,
        ):

            username = key[len("smtp:user:"):]

            config = self.get_user_config(
                username
            )

            if config:
                users.append(config)

        return sorted(
            users,
            key=lambda item: item["username"],
        )

    # =========================================================
    # Rate bucket
    # =========================================================

    def get_time_buckets(self):

        now = datetime.now(
            self.TIMEZONE
        )

        minute_bucket = now.strftime(
            "%Y%m%d%H%M"
        )

        hour_bucket = now.strftime(
            "%Y%m%d%H"
        )

        day_bucket = now.strftime(
            "%Y%m%d"
        )

        next_minute = (
            now.replace(
                second=0,
                microsecond=0,
            )
            + timedelta(minutes=1)
        )

        next_hour = (
            now.replace(
                minute=0,
                second=0,
                microsecond=0,
            )
            + timedelta(hours=1)
        )

        next_day = (
            now.replace(
                hour=0,
                minute=0,
                second=0,
                microsecond=0,
            )
            + timedelta(days=1)
        )

        minute_ttl = max(
            1,
            int(
                (
                    next_minute - now
                ).total_seconds()
            ) + 2,
        )

        hour_ttl = max(
            1,
            int(
                (
                    next_hour - now
                ).total_seconds()
            ) + 2,
        )

        day_ttl = max(
            1,
            int(
                (
                    next_day - now
                ).total_seconds()
            ) + 2,
        )

        return (
            minute_bucket,
            hour_bucket,
            day_bucket,
            minute_ttl,
            hour_ttl,
            day_ttl,
        )

    # =========================================================
    # Current usage
    # =========================================================

    def get_current_usage(
        self,
        username: str,
    ):

        username = self.validate_username(
            username
        )

        config = self.get_user_config(
            username
        )

        if config is None:
            return None

        (
            minute_bucket,
            hour_bucket,
            day_bucket,
            _,
            _,
            _,
        ) = self.get_time_buckets()

        minute_key = (
            f"smtp:rate:{username}:"
            f"minute:{minute_bucket}"
        )

        hour_key = (
            f"smtp:rate:{username}:"
            f"hour:{hour_bucket}"
        )

        day_key = (
            f"smtp:rate:{username}:"
            f"day:{day_bucket}"
        )

        minute_count = int(
            self.redis.get(minute_key) or 0
        )

        hour_count = int(
            self.redis.get(hour_key) or 0
        )

        day_count = int(
            self.redis.get(day_key) or 0
        )

        return {
            "username": username,
            "minute": {
                "used": minute_count,
                "limit": config["minute_limit"],
            },
            "hour": {
                "used": hour_count,
                "limit": config["hour_limit"],
            },
            "day": {
                "used": day_count,
                "limit": config["day_limit"],
            },
        }

    # =========================================================
    # Policy decision
    # =========================================================

    def check_rate_limit(
        self,
        username: str,
    ):

        username = self.clean_username(
            username
        )

        config = self.get_user_config(
            username
        )

        # Fail closed if user is not configured.
        if config is None:

            logger.warning(
                "REJECT user=%s reason=unauthorized",
                username,
            )

            return (
                False,
                "554 5.7.1 SMTP user is not authorized by policy",
            )

        if not config["enabled"]:

            logger.warning(
                "REJECT user=%s reason=disabled",
                username,
            )

            return (
                False,
                "554 5.7.1 SMTP user is disabled",
            )

        (
            minute_bucket,
            hour_bucket,
            day_bucket,
            minute_ttl,
            hour_ttl,
            day_ttl,
        ) = self.get_time_buckets()

        minute_key = (
            f"smtp:rate:{username}:"
            f"minute:{minute_bucket}"
        )

        hour_key = (
            f"smtp:rate:{username}:"
            f"hour:{hour_bucket}"
        )

        day_key = (
            f"smtp:rate:{username}:"
            f"day:{day_bucket}"
        )

        try:

            result = self.rate_limit_script(
                keys=[
                    minute_key,
                    hour_key,
                    day_key,
                ],
                args=[
                    config["minute_limit"],
                    config["hour_limit"],
                    config["day_limit"],
                    minute_ttl,
                    hour_ttl,
                    day_ttl,
                ],
            )

        except Exception as exc:

            logger.exception(
                "REDIS_ERROR user=%s error=%s",
                username,
                exc,
            )

            # Fail closed.
            return (
                False,
                "451 4.3.5 SMTP policy service temporarily unavailable",
            )

        result = int(result)

        if result == 0:

            logger.info(
                "ALLOW user=%s minute=%s hour=%s day=%s",
                username,
                config["minute_limit"],
                config["hour_limit"],
                config["day_limit"],
            )

            return (
                True,
                "DUNNO",
            )

        if result == 1:

            logger.warning(
                "REJECT user=%s reason=minute_limit",
                username,
            )

            return (
                False,
                "554 5.7.1 SMTP rate limit exceeded: "
                f"{config['minute_limit']} messages/minute",
            )

        if result == 2:

            logger.warning(
                "REJECT user=%s reason=hour_limit",
                username,
            )

            return (
                False,
                "554 5.7.1 SMTP rate limit exceeded: "
                f"{config['hour_limit']} messages/hour",
            )

        if result == 3:

            logger.warning(
                "REJECT user=%s reason=day_limit",
                username,
            )

            return (
                False,
                "554 5.7.1 SMTP rate limit exceeded: "
                f"{config['day_limit']} messages/day",
            )

        logger.error(
            "Unexpected Redis result=%s user=%s",
            result,
            username,
        )

        return (
            False,
            "451 4.3.5 SMTP policy service error",
        )
    # =========================================================
    # non-consuming policy simulation
    # =========================================================
    def simulate_policy(self, username: str):
        username = self.validate_username(username)

        config = self.get_user_config(username)

        if config is None:
            return {
                "allowed": False,
                "response": (
                    "554 5.7.1 SMTP user is not authorized by policy"
                ),
                "reason": "user_not_configured",
                "usage": None,
            }

        if not config["enabled"]:
            return {
                "allowed": False,
                "response": "554 5.7.1 SMTP user is disabled",
                "reason": "user_disabled",
                "usage": None,
            }

        usage = self.get_current_usage(username)

        if usage["minute"]["used"] >= usage["minute"]["limit"]:
            return {
                "allowed": False,
                "response": (
                    "554 5.7.1 SMTP rate limit exceeded: "
                    f"{config['minute_limit']} messages/minute"
                ),
                "reason": "minute_limit",
                "usage": usage,
            }

        if usage["hour"]["used"] >= usage["hour"]["limit"]:
            return {
                "allowed": False,
                "response": (
                    "554 5.7.1 SMTP rate limit exceeded: "
                    f"{config['hour_limit']} messages/hour"
                ),
                "reason": "hour_limit",
                "usage": usage,
            }

        if usage["day"]["used"] >= usage["day"]["limit"]:
            return {
                "allowed": False,
                "response": (
                    "554 5.7.1 SMTP rate limit exceeded: "
                    f"{config['day_limit']} messages/day"
                ),
                "reason": "day_limit",
                "usage": usage,
            }

        return {
            "allowed": True,
            "response": "DUNNO",
            "reason": "within_limits",
            "usage": usage,
        }