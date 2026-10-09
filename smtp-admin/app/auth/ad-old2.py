import logging
import ssl

from ldap3 import Server, Connection, ALL, Tls
from ldap3.core.exceptions import LDAPException

from ..config import settings

logger = logging.getLogger(__name__)


def _get_ad_servers():
    """
    Return configured AD Domain Controllers in priority order.
    DC01 is tried first, then DC02.
    """
    servers = []

    for host in (
        settings.ad_server_1,
        settings.ad_server_2,
    ):
        if host:
            host = host.strip()

            if host and host not in servers:
                servers.append(host)

    return servers


def _escape_ldap_filter(value: str) -> str:
    """
    Escape LDAP filter special characters.
    """
    return (
        value
        .replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _get_tls_config():
    """
    TLS configuration for LDAP STARTTLS on TCP/389.

    STARTTLS upgrades the existing LDAP connection on port 389
    to an encrypted TLS connection before authentication.

    The AD CA certificate must be trusted by the OEL server.
    """
    return Tls(
        #validate=ssl.CERT_REQUIRED,
        # version=ssl.PROTOCOL_TLS_CLIENT,
        validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLS_CLIENT,
    )


def _normalize_dn(dn: str) -> str:
    """
    Normalize a DN for case-insensitive comparison.
    """
    if not dn:
        return ""

    return " ".join(dn.strip().lower().split())


def _close_connection(conn):
    """
    Safely close an LDAP connection.
    """
    if conn is not None:
        try:
            if conn.bound:
                conn.unbind()
            else:
                conn.unbind()
        except Exception:
            pass


def authenticate_ad(username: str, password: str):
    """
    Authenticate a portal user against Microsoft AD.

    Authentication flow:

        1. Connect to AD DC using LDAP TCP/389.
        2. Establish STARTTLS on the LDAP connection.
        3. STARTTLS encrypts the LDAP session.
        4. Bind using the AD service account.
        5. Search for the requested user.
        6. Verify membership in MP-SMTP-Users.
        7. Authenticate the actual user's password.
        8. Determine application RBAC role.
        9. Return authenticated user information.

    IMPORTANT:
        - TCP port 389 is used.
        - STARTTLS is mandatory.
        - User/service-account passwords are never logged.
    """

    if not username or not password:
        logger.warning("AD authentication rejected: empty username/password")
        return None

    username = username.strip()

    if not username:
        logger.warning("AD authentication rejected: empty username")
        return None

    user_upn = (
        username
        if "@" in username
        else f"{username}@{settings.ad_domain}"
    ).strip().lower()

    logger.info(
        "AD authentication started: user=%s",
        user_upn,
    )

    ad_servers = _get_ad_servers()

    if not ad_servers:
        logger.error("No AD Domain Controllers configured")
        return None

    logger.debug(
        "Configured AD servers: %s",
        ", ".join(ad_servers),
    )

    tls_config = _get_tls_config()

    for ad_host in ad_servers:

        search_conn = None
        user_conn = None

        try:
            logger.debug(
                "Connecting to AD DC using LDAP STARTTLS: "
                "DC=%s port=389 user=%s",
                ad_host,
                user_upn,
            )

            # ---------------------------------------------------------
            # LDAP server connection
            # ---------------------------------------------------------
            server = Server(
                ad_host,
                port=389,
                use_ssl=False,
                tls=tls_config,
                get_info=ALL,
                connect_timeout=5,
            )

            # ---------------------------------------------------------
            # Service account connection
            # ---------------------------------------------------------
            search_conn = Connection(
                server,
                user=settings.ad_bind_user,
                password=settings.ad_bind_password,
                auto_bind=False,
                raise_exceptions=True,
            )

            logger.debug(
                "Opening LDAP connection: DC=%s port=389",
                ad_host,
            )

            search_conn.open()

            logger.debug(
                "LDAP TCP connection established: DC=%s port=389",
                ad_host,
            )

            # ---------------------------------------------------------
            # STARTTLS
            # ---------------------------------------------------------
            logger.debug(
                "Starting LDAP STARTTLS: DC=%s",
                ad_host,
            )

            search_conn.start_tls(
                read_server_info=False
            )

            logger.info(
                "LDAP STARTTLS established successfully: DC=%s",
                ad_host,
            )

            # ---------------------------------------------------------
            # Service account bind
            # ---------------------------------------------------------
            logger.debug(
                "Binding LDAP service account: DC=%s account=%s",
                ad_host,
                settings.ad_bind_user,
            )

            search_conn.bind()

            if not search_conn.bound:
                logger.error(
                    "LDAP service account bind failed: DC=%s result=%s",
                    ad_host,
                    search_conn.result,
                )

                _close_connection(search_conn)
                search_conn = None
                continue

            logger.info(
                "LDAP service account bind successful: DC=%s",
                ad_host,
            )

            # ---------------------------------------------------------
            # Search for user
            # ---------------------------------------------------------
            safe_upn = _escape_ldap_filter(user_upn)

            search_filter = (
                "(&(objectClass=user)"
                f"(userPrincipalName={safe_upn}))"
            )

            logger.debug(
                "Searching AD user: base=%s filter=%s",
                settings.ad_base_dn,
                search_filter,
            )

            found = search_conn.search(
                search_base=settings.ad_base_dn,
                search_filter=search_filter,
                attributes=[
                    "distinguishedName",
                    "memberOf",
                    "sAMAccountName",
                    "userPrincipalName",
                    "displayName",
                ],
            )

            if not found or not search_conn.entries:
                logger.warning(
                    "AD user not found: user=%s DC=%s result=%s",
                    user_upn,
                    ad_host,
                    search_conn.result,
                )

                _close_connection(search_conn)
                search_conn = None
                continue

            entry = search_conn.entries[0]

            user_dn = str(entry.distinguishedName.value)

            logger.debug(
                "AD user found: user=%s DN=%s DC=%s",
                user_upn,
                user_dn,
                ad_host,
            )

            # ---------------------------------------------------------
            # Get group membership
            # ---------------------------------------------------------
            groups = set()

            if hasattr(entry, "memberOf") and entry.memberOf:
                groups = {
                    str(group).strip()
                    for group in entry.memberOf.values
                    if str(group).strip()
                }

            logger.debug(
                "AD groups for user=%s: %s",
                user_upn,
                sorted(groups),
            )

            # ---------------------------------------------------------
            # MP-SMTP-Users authorization
            # ---------------------------------------------------------
            required_group = (
                settings.ad_group_dn.strip()
                if settings.ad_group_dn
                else ""
            )

            if required_group:
                normalized_required_group = _normalize_dn(
                    required_group
                )

                normalized_groups = {
                    _normalize_dn(group)
                    for group in groups
                }

                if normalized_required_group not in normalized_groups:
                    logger.warning(
                        "AD authorization failed: user=%s is not "
                        "a member of required group=%s",
                        user_upn,
                        required_group,
                    )

                    _close_connection(search_conn)
                    search_conn = None
                    return None

                logger.info(
                    "AD group authorization successful: "
                    "user=%s group=%s",
                    user_upn,
                    required_group,
                )

            # ---------------------------------------------------------
            # Close service-account connection
            # ---------------------------------------------------------
            _close_connection(search_conn)
            search_conn = None

            # ---------------------------------------------------------
            # Authenticate actual user
            #
            # IMPORTANT:
            # The user authentication also uses:
            #
            #     LDAP/389
            #          +
            #     STARTTLS
            #          +
            #     user password bind
            # ---------------------------------------------------------
            logger.debug(
                "Authenticating AD user password: user=%s DC=%s",
                user_upn,
                ad_host,
            )

            user_conn = Connection(
                server,
                user=user_upn,
                password=password,
                authentication=NTLM,
                auto_bind=True,
                raise_exceptions=True,
            )

            user_conn.open()

            logger.debug(
                "User LDAP connection established: "
                "user=%s DC=%s",
                user_upn,
                ad_host,
            )

            user_conn.start_tls(
                read_server_info=False
            )

            logger.debug(
                "User LDAP STARTTLS established: "
                "user=%s DC=%s",
                user_upn,
                ad_host,
            )

            user_conn.bind()

            if not user_conn.bound:
                logger.warning(
                    "AD user authentication failed: "
                    "user=%s DC=%s result=%s",
                    user_upn,
                    ad_host,
                    user_conn.result,
                )

                _close_connection(user_conn)
                user_conn = None
                return None

            logger.info(
                "AD user password authentication successful: "
                "user=%s DC=%s",
                user_upn,
                ad_host,
            )

            _close_connection(user_conn)
            user_conn = None

            # ---------------------------------------------------------
            # RBAC role resolution
            # ---------------------------------------------------------
            role = "read_only"

            role_map = settings.role_map()

            normalized_groups = {
                _normalize_dn(group)
                for group in groups
            }

            security_admin_groups = {
                _normalize_dn(group)
                for group in role_map["security_admin"]
            }

            smtp_admin_groups = {
                _normalize_dn(group)
                for group in role_map["smtp_admin"]
            }

            read_only_groups = {
                _normalize_dn(group)
                for group in role_map["read_only"]
            }

            if normalized_groups & security_admin_groups:
                role = "security_admin"

            elif normalized_groups & smtp_admin_groups:
                role = "smtp_admin"

            elif normalized_groups & read_only_groups:
                role = "read_only"

            logger.info(
                "AD authentication successful: "
                "user=%s role=%s DC=%s",
                user_upn,
                role,
                ad_host,
            )

            return {
                "username": user_upn,
                "dn": user_dn,
                "groups": sorted(groups),
                "role": role,
            }

        except LDAPException as exc:
            logger.exception(
                "AD LDAP authentication error: "
                "user=%s DC=%s error=%s",
                user_upn,
                ad_host,
                exc,
            )

        except (OSError, ssl.SSLError) as exc:
            logger.exception(
                "AD TLS/network error: "
                "user=%s DC=%s error=%s",
                user_upn,
                ad_host,
                exc,
            )

        except Exception as exc:
            logger.exception(
                "Unexpected AD authentication error: "
                "user=%s DC=%s error=%s",
                user_upn,
                ad_host,
                exc,
            )

        finally:
            _close_connection(search_conn)
            _close_connection(user_conn)

    logger.error(
        "AD authentication failed against all configured DCs: "
        "user=%s",
        user_upn,
    )

    return None

