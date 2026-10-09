import socket


class SmtpPolicyTestService:
    HOST = "127.0.0.1"
    PORT = 10031
    TIMEOUT = 5

    def test_listener(self, username: str):
        username = (username or "").strip().lower()

        if not username or "\n" in username or "\r" in username:
            raise ValueError("Invalid SMTP username")

        request = (
            "request=smtpd_access_policy\n"
            f"sasl_username={username}\n"
            f"sender={username}\n"
            "recipient=policy-test@muktopay.com\n"
            "client_address=127.0.0.1\n"
            "\n"
        )

        with socket.create_connection(
            (self.HOST, self.PORT),
            timeout=self.TIMEOUT,
        ) as sock:
            sock.settimeout(self.TIMEOUT)
            sock.sendall(request.encode("utf-8"))

            response = bytearray()

            while b"\n\n" not in response:
                chunk = sock.recv(4096)

                if not chunk:
                    break

                response.extend(chunk)

                if len(response) > 8192:
                    raise RuntimeError(
                        "Policy listener response was too large"
                    )

        result = response.decode(
            "utf-8",
            errors="replace",
        ).strip()

        if not result:
            raise RuntimeError(
                "Policy listener returned an empty response"
            )

        return result