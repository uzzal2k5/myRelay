#!/usr/bin/env python3

import logging
import socket

from ..services.smtp_policy_service import (
    SmtpPolicyService,
)


logger = logging.getLogger(
    "my-relay.smtp-policy.server"
)


LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 10031

MAX_REQUEST_SIZE = 65536


policy_service = SmtpPolicyService()


def parse_request(data: str):

    request = {}

    for line in data.splitlines():

        line = line.strip()

        if not line:
            continue

        if "=" not in line:
            continue

        key, value = line.split(
            "=",
            1,
        )

        request[key.strip()] = value.strip()

    return request


def process_request(data: str):

    request = parse_request(data)

    request_type = request.get(
        "request",
        "",
    )

    username = (
        policy_service.clean_username(
            request.get(
                "sasl_username",
                "",
            )
        )
    )

    client_address = request.get(
        "client_address",
        "-",
    )

    sender = request.get(
        "sender",
        "-",
    )

    recipient = request.get(
        "recipient",
        "-",
    )

    logger.info(
        "REQUEST type=%s user=%s client=%s "
        "sender=%s recipient=%s",
        request_type,
        username,
        client_address,
        sender,
        recipient,
    )

    # We only handle smtpd_access_policy.
    if request_type != "smtpd_access_policy":

        return "DUNNO\n\n"

    # Authentication should already be enforced
    # by Postfix submission configuration.
    if not username:

        logger.warning(
            "REJECT unauthenticated request "
            "client=%s sender=%s recipient=%s",
            client_address,
            sender,
            recipient,
        )

        return (
            "554 5.7.1 SMTP authentication required\n\n"
        )

    allowed, response = (
        policy_service.check_rate_limit(
            username
        )
    )

    if allowed:

        logger.info(
            "POLICY ALLOW user=%s client=%s",
            username,
            client_address,
        )

    else:

        logger.warning(
            "POLICY REJECT user=%s client=%s "
            "response=%s",
            username,
            client_address,
            response,
        )

    return f"{response}\n\n"


def handle_client(
    conn: socket.socket,
    address,
):

    client_ip = address[0]

    logger.info(
        "POLICY CONNECT client=%s",
        client_ip,
    )

    buffer = bytearray()

    try:

        conn.settimeout(10)

        while True:

            data = conn.recv(4096)

            if not data:
                break

            buffer.extend(data)

            if len(buffer) > MAX_REQUEST_SIZE:

                logger.warning(
                    "POLICY REQUEST TOO LARGE "
                    "client=%s",
                    client_ip,
                )

                try:
                    conn.sendall(
                        (
                            "451 4.3.5 SMTP policy "
                            "request too large\n\n"
                        ).encode()
                    )
                finally:
                    break

            if b"\n\n" not in buffer:
                continue

            request_data = buffer.decode(
                "utf-8",
                errors="replace",
            )

            response = process_request(
                request_data
            )

            conn.sendall(
                response.encode("utf-8")
            )

            break

    except socket.timeout:

        logger.warning(
            "POLICY TIMEOUT client=%s",
            client_ip,
        )

    except Exception as exc:

        logger.exception(
            "POLICY CLIENT ERROR "
            "client=%s error=%s",
            client_ip,
            exc,
        )

    finally:

        try:
            conn.close()
        except Exception:
            pass

        logger.info(
            "POLICY DISCONNECT client=%s",
            client_ip,
        )


def start_server():

    logger.info(
        "Starting My Relay SMTP Policy "
        "listener=%s:%s Redis=%s:%s DB=%s",
        LISTEN_HOST,
        LISTEN_PORT,
        policy_service.REDIS_HOST,
        policy_service.REDIS_PORT,
        policy_service.REDIS_DB,
    )

    # Fail startup if Redis is unavailable.
    try:

        policy_service.redis.ping()

        logger.info(
            "Redis connection successful"
        )

    except Exception as exc:

        logger.exception(
            "Unable to connect to Redis: %s",
            exc,
        )

        raise

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    # Explicitly bind only to localhost.
    server.bind(
        (
            LISTEN_HOST,
            LISTEN_PORT,
        )
    )

    server.listen(20)

    logger.info(
        "My Relay SMTP Policy listening "
        "on %s:%s",
        LISTEN_HOST,
        LISTEN_PORT,
    )

    try:

        while True:

            conn, address = server.accept()

            handle_client(
                conn,
                address,
            )

    except KeyboardInterrupt:

        logger.info(
            "SMTP Policy service stopped"
        )

    finally:

        server.close()


if __name__ == "__main__":

    start_server()