"""
LDAP / Active Directory configuration inspection and diagnostics.

This service is deliberately read-only with respect to configuration: it
reports what the application is configured with (never the bind password),
and offers two diagnostics - a connection test and a directory lookup for one
user. Neither diagnostic handles a user's password.
"""
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from ldap3 import BASE, NONE, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn


logger = logging.getLogger(__name__)


# The Settings model's field names for LDAP were not known when this was
# written, so each value is looked up under several likely names. Add your
# real names to the front of a list if none of these match.
SERVER_NAMES = ["ldap_server", "ldap_host", "ldap_uri", "ldap_url", "ad_server", "ad_host"]
PORT_NAMES = ["ldap_port", "ad_port"]
SSL_NAMES = ["ldap_use_ssl", "ldap_ssl", "ad_use_ssl"]
STARTTLS_NAMES = ["ldap_start_tls", "ldap_use_starttls", "ad_start_tls"]
VERIFY_NAMES = ["ldap_verify_cert", "ldap_tls_verify", "ad_verify_cert"]
CA_FILE_NAMES = ["ldap_ca_certs_file", "ldap_ca_file", "ldap_ca_cert"]
BASE_DN_NAMES = ["ldap_base_dn", "ad_base_dn", "ldap_search_base"]
BIND_DN_NAMES = ["ldap_bind_dn", "ldap_bind_user", "ldap_service_account", "ad_bind_dn", "ad_bind_user"]
BIND_PASSWORD_NAMES = ["ldap_bind_password", "ldap_bind_pw", "ldap_password", "ad_bind_password"]
DOMAIN_NAMES = ["ad_domain", "ldap_domain"]
GROUP_NAMES = ["ldap_required_group", "ldap_allowed_group", "ad_required_group", "ldap_access_group"]
USER_ATTR_NAMES = ["ldap_user_attribute", "ldap_login_attribute", "ad_user_attribute"]
TIMEOUT_NAMES = ["ldap_timeout", "ad_timeout"]

DEFAULT_REQUIRED_GROUP = "MP-SMTP-Users"
DEFAULT_USER_ATTRIBUTE = "sAMAccountName"
DEFAULT_TIMEOUT = 5

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._\-$]{1,64}$")
ATTRIBUTE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9\-]{0,63}$")
MAX_GROUPS_SHOWN = 50

# Active Directory "extended error" codes that appear as "data 52e" in a
# failed bind message. These are the ones administrators actually hit.
AD_BIND_HINTS = {
    "52e": "The bind account's username or password is wrong.",
    "525": "The bind account does not exist.",
    "530": "The bind account is not allowed to sign in at this time.",
    "531": "The bind account is not allowed to sign in from this host.",
    "532": "The bind account's password has expired.",
    "533": "The bind account is disabled.",
    "701": "The bind account has expired.",
    "773": "The bind account must change its password before it can sign in.",
    "775": "The bind account is locked out.",
}

# Matching rule that makes AD expand nested group membership server-side.
AD_IN_CHAIN_RULE = "1.2.840.113556.1.4.1941"

_TRUE_VALUES = {"1", "true", "yes", "on"}


class LdapConfigError(Exception):
    """A diagnostic could not be completed. The message is safe to show."""


def _pick(source: Any, names: List[str]) -> Any:
    for name in names:
        value = getattr(source, name, None)
        if hasattr(value, "get_secret_value"):
            value = value.get_secret_value()
        if value is None or value == "":
            continue
        return value
    return None


def _as_bool(value: Any, default: Optional[bool]) -> Optional[bool]:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUE_VALUES


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass
class LdapSettings:
    host: Optional[str]
    port: int
    use_ssl: bool
    start_tls: bool
    verify_cert: bool
    ca_file: Optional[str]
    base_dn: Optional[str]
    bind_dn: Optional[str]
    # repr=False so the password can never leak through a log line or
    # a traceback that prints this object.
    bind_password: Optional[str] = field(repr=False)
    domain: Optional[str]
    required_group: str
    user_attribute: str
    timeout: int
    missing: List[str]

    @property
    def transport(self) -> str:
        if self.use_ssl:
            return "LDAPS"
        if self.start_tls:
            return "StartTLS"
        return "Plain LDAP"

    @property
    def encrypted(self) -> bool:
        return self.use_ssl or self.start_tls

    def describe(self) -> Dict[str, Any]:
        """Everything the page may display. The bind password is never included."""
        return {
            "server": self.host,
            "port": self.port,
            "transport": self.transport,
            "encrypted": self.encrypted,
            "verify_cert": self.verify_cert,
            "base_dn": self.base_dn,
            "bind_dn": self.bind_dn,
            "bind_password_set": bool(self.bind_password),
            "domain": self.domain,
            "required_group": self.required_group,
            "user_attribute": self.user_attribute,
            "timeout": self.timeout,
            "missing": list(self.missing),
        }


def load_ldap_settings(source: Any) -> LdapSettings:
    host: Optional[str] = None
    uri_ssl: Optional[bool] = None
    uri_port: Optional[int] = None

    raw_server = _pick(source, SERVER_NAMES)
    if raw_server:
        # A failover list ("ldaps://a ldaps://b") is common; test the first.
        first = str(raw_server).replace(",", " ").split()[0]
        if "://" in first:
            parsed = urlparse(first)
            host = parsed.hostname
            uri_ssl = parsed.scheme.lower() == "ldaps"
            uri_port = parsed.port
        else:
            host, _, port_text = first.partition(":")
            uri_port = _as_int(port_text)

    port = _as_int(_pick(source, PORT_NAMES)) or uri_port

    use_ssl = _as_bool(_pick(source, SSL_NAMES), None)
    if use_ssl is None:
        use_ssl = bool(uri_ssl) or port == 636

    if not port:
        port = 636 if use_ssl else 389

    start_tls = bool(_as_bool(_pick(source, STARTTLS_NAMES), False)) and not use_ssl

    user_attribute = str(_pick(source, USER_ATTR_NAMES) or DEFAULT_USER_ATTRIBUTE)
    if not ATTRIBUTE_PATTERN.match(user_attribute):
        user_attribute = DEFAULT_USER_ATTRIBUTE

    base_dn = _pick(source, BASE_DN_NAMES)
    bind_dn = _pick(source, BIND_DN_NAMES)
    bind_password = _pick(source, BIND_PASSWORD_NAMES)

    missing = [
        label
        for label, value in (
            ("server", host),
            ("base DN", base_dn),
            ("bind account", bind_dn),
            ("bind password", bind_password),
        )
        if not value
    ]

    return LdapSettings(
        host=host,
        port=port,
        use_ssl=use_ssl,
        start_tls=start_tls,
        verify_cert=bool(_as_bool(_pick(source, VERIFY_NAMES), True)),
        ca_file=_pick(source, CA_FILE_NAMES),
        base_dn=base_dn,
        bind_dn=bind_dn,
        bind_password=bind_password,
        domain=_pick(source, DOMAIN_NAMES),
        required_group=str(_pick(source, GROUP_NAMES) or DEFAULT_REQUIRED_GROUP),
        user_attribute=user_attribute,
        timeout=_as_int(_pick(source, TIMEOUT_NAMES)) or DEFAULT_TIMEOUT,
        missing=missing,
    )


def _explain(exc: Exception) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    text = text[:300]

    if "CERTIFICATE_VERIFY_FAILED" in text:
        text += (
            " The server certificate is not trusted by this host. Install your "
            "CA certificate in the system trust store, or set the CA file "
            "setting to its path."
        )
    elif "timed out" in text.lower():
        text += " Check that the server is reachable and the port is open in the firewall."
    elif "refused" in text.lower():
        text += " Nothing is listening on that host and port."

    return text


def _bind_failure_message(conn: Connection) -> str:
    result = conn.result or {}
    description = result.get("description") or "bind failed"
    message = result.get("message") or ""

    match = re.search(r"data ([0-9a-fA-F]{3})", message)
    hint = AD_BIND_HINTS.get(match.group(1).lower()) if match else None

    if hint:
        return f"{description}. {hint}"
    if message:
        return f"{description}: {message[:200]}"
    return description


def _step(name: str, ok: bool, detail: str) -> Dict[str, Any]:
    return {"name": name, "ok": ok, "detail": detail}


def _first(values: Optional[List[Any]]) -> Optional[str]:
    if not values:
        return None
    value = values[0]
    return None if value is None or value == "" else str(value)


def _rdn_value(dn: str) -> str:
    try:
        return str(parse_dn(dn)[0][1])
    except Exception:
        return dn.split(",")[0].split("=", 1)[-1]


class LdapConfigService:
    def __init__(
        self,
        cfg: LdapSettings,
        connection_factory: Optional[Callable[[LdapSettings], Connection]] = None,
    ):
        self.cfg = cfg
        # Tests inject an in-memory connection here; production leaves it None.
        self._connection_factory = connection_factory

    # -----------------------------------------------------------------
    # Connection helpers
    # -----------------------------------------------------------------

    def _config_problem(self) -> Optional[str]:
        if self.cfg.missing:
            return (
                "These settings could not be found: "
                + ", ".join(self.cfg.missing)
                + ". Check the LDAP field names in config.py."
            )
        return None

    def _new_connection(self) -> Connection:
        if self._connection_factory:
            return self._connection_factory(self.cfg)

        cfg = self.cfg
        tls = None
        if cfg.encrypted:
            tls = Tls(
                validate=ssl.CERT_REQUIRED if cfg.verify_cert else ssl.CERT_NONE,
                ca_certs_file=cfg.ca_file,
            )

        server = Server(
            cfg.host,
            port=cfg.port,
            use_ssl=cfg.use_ssl,
            tls=tls,
            get_info=NONE,
            connect_timeout=cfg.timeout,
        )
        return Connection(
            server,
            user=cfg.bind_dn,
            password=cfg.bind_password,
            authentication=SIMPLE,
            receive_timeout=cfg.timeout,
            raise_exceptions=False,
        )

    def _open(self, conn: Connection) -> None:
        try:
            conn.open()
            if self.cfg.start_tls and not self.cfg.use_ssl and not conn.start_tls():
                raise LdapConfigError("The server refused the StartTLS request.")
        except LdapConfigError:
            raise
        except (LDAPException, OSError) as exc:
            raise LdapConfigError(_explain(exc)) from exc

    def _bind(self, conn: Connection) -> None:
        try:
            bound = conn.bind()
        except (LDAPException, OSError) as exc:
            raise LdapConfigError(_explain(exc)) from exc

        if not bound:
            raise LdapConfigError(_bind_failure_message(conn))

    @staticmethod
    def _close(conn: Optional[Connection]) -> None:
        if conn is None:
            return
        try:
            conn.unbind()
        except Exception:
            pass

    # -----------------------------------------------------------------
    # Diagnostics
    # -----------------------------------------------------------------

    def test_connection(self) -> Dict[str, Any]:
        """Connect, bind as the service account, and read the base DN."""
        started = time.monotonic()
        steps: List[Dict[str, Any]] = []

        def finish(ok: bool) -> Dict[str, Any]:
            return {
                "ok": ok,
                "steps": steps,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }

        problem = self._config_problem()
        if problem:
            steps.append(_step("Read configuration", False, problem))
            return finish(False)

        cfg = self.cfg
        conn: Optional[Connection] = None

        try:
            conn = self._new_connection()

            try:
                self._open(conn)
            except LdapConfigError as exc:
                steps.append(_step("Connect to server", False, str(exc)))
                return finish(False)
            steps.append(
                _step("Connect to server", True, f"Reached {cfg.host}:{cfg.port} over {cfg.transport}.")
            )

            try:
                self._bind(conn)
            except LdapConfigError as exc:
                steps.append(_step("Sign in as the bind account", False, str(exc)))
                return finish(False)
            steps.append(_step("Sign in as the bind account", True, "The bind account was accepted."))

            found = conn.search(
                cfg.base_dn,
                "(objectClass=*)",
                search_scope=BASE,
                attributes=["distinguishedName"],
                size_limit=1,
            )
            if not found:
                description = (conn.result or {}).get("description") or "not found"
                steps.append(
                    _step(
                        "Read the base DN",
                        False,
                        f"The base DN could not be read ({description}). "
                        "Check its spelling and that the bind account may read it.",
                    )
                )
                return finish(False)
            steps.append(_step("Read the base DN", True, "The search base exists and is readable."))

            return finish(True)

        except Exception as exc:
            logger.exception("Unexpected error during LDAP connection test")
            steps.append(_step("Run the test", False, _explain(exc)))
            return finish(False)
        finally:
            self._close(conn)

    def lookup_user(self, raw_username: str) -> Dict[str, Any]:
        """
        Find one user in the directory and report whether they meet the
        access-group requirement. Directory-level only: it does not check a
        password and does not evaluate how groups map to application roles.
        """
        username = (raw_username or "").strip()
        if "\\" in username:
            username = username.split("\\")[-1]
        if "@" in username:
            username = username.split("@")[0]

        if not USERNAME_PATTERN.match(username):
            raise ValueError(
                "Enter the account name only (letters, digits, dot, dash, underscore), up to 64 characters."
            )

        problem = self._config_problem()
        if problem:
            raise LdapConfigError(problem)

        cfg = self.cfg
        conn: Optional[Connection] = None

        try:
            conn = self._new_connection()
            self._open(conn)
            self._bind(conn)

            escaped_user = escape_filter_chars(username)
            user_filter = (
                f"(&(objectCategory=person)(objectClass=user)({cfg.user_attribute}={escaped_user}))"
            )

            conn.search(
                cfg.base_dn,
                user_filter,
                search_scope=SUBTREE,
                attributes=[
                    "displayName",
                    "mail",
                    "memberOf",
                    "userAccountControl",
                    cfg.user_attribute,
                ],
                size_limit=2,
            )

            entries = list(conn.entries)
            result: Dict[str, Any] = {
                "username": username,
                "found": bool(entries),
                "ambiguous": len(entries) > 1,
                "dn": None,
                "display_name": None,
                "mail": None,
                "enabled": None,
                "groups": [],
                "groups_truncated": False,
                "required_group": cfg.required_group,
                "in_required_group": None,
                "group_found": None,
            }

            if not entries:
                return result

            entry = entries[0]
            attrs = entry.entry_attributes_as_dict

            result["dn"] = entry.entry_dn
            result["display_name"] = _first(attrs.get("displayName"))
            result["mail"] = _first(attrs.get("mail"))

            uac = _as_int(_first(attrs.get("userAccountControl")))
            if uac is not None:
                result["enabled"] = (uac & 0x2) == 0

            member_of = [str(dn) for dn in attrs.get("memberOf", [])]
            names = sorted({_rdn_value(dn) for dn in member_of}, key=str.lower)
            result["groups"] = names[:MAX_GROUPS_SHOWN]
            result["groups_truncated"] = len(names) > MAX_GROUPS_SHOWN

            required = cfg.required_group.lower()
            in_group = any(name.lower() == required for name in names)
            group_dn = None

            if not in_group:
                group_dn = self._find_group_dn(conn, cfg.required_group)
                if group_dn:
                    in_group = self._is_member_via_chain(conn, escaped_user, group_dn)

            result["in_required_group"] = in_group
            result["group_found"] = in_group or group_dn is not None

            return result

        except LdapConfigError:
            raise
        except LDAPException as exc:
            raise LdapConfigError(_explain(exc)) from exc
        finally:
            self._close(conn)

    # -----------------------------------------------------------------
    # Group helpers
    # -----------------------------------------------------------------

    def _find_group_dn(self, conn: Connection, group_name: str) -> Optional[str]:
        escaped = escape_filter_chars(group_name)
        try:
            conn.search(
                self.cfg.base_dn,
                f"(&(objectClass=group)(|(cn={escaped})(sAMAccountName={escaped})))",
                search_scope=SUBTREE,
                attributes=["distinguishedName"],
                size_limit=1,
            )
            return conn.entries[0].entry_dn if conn.entries else None
        except LDAPException:
            logger.warning("Group lookup failed for the required group", exc_info=False)
            return None

    def _is_member_via_chain(self, conn: Connection, escaped_user: str, group_dn: str) -> bool:
        """
        True if the user belongs to the group directly or through nested
        groups. Uses an AD-specific matching rule; on a directory that does
        not support it the search simply fails and this returns False.
        """
        try:
            conn.search(
                self.cfg.base_dn,
                (
                    f"(&(objectCategory=person)(objectClass=user)"
                    f"({self.cfg.user_attribute}={escaped_user})"
                    f"(memberOf:{AD_IN_CHAIN_RULE}:={escape_filter_chars(group_dn)}))"
                ),
                search_scope=SUBTREE,
                attributes=["distinguishedName"],
                size_limit=1,
            )
            return bool(conn.entries)
        except LDAPException:
            logger.warning("Nested group membership check failed", exc_info=False)
            return False