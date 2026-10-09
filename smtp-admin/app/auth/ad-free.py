import logging
from typing import Optional

from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPException

from app.config import settings


logger = logging.getLogger(__name__)


def _get_ad_servers():
    """
    Return configured AD domain controllers.
    """
    servers = []

    # Preferred configuration
    if hasattr(settings, "ad_servers"):
        configured = settings.ad_servers

        if isinstance(configured, str):
            configured = [
                x.strip()
                for x in configured.split(",")
                if x.strip()
            ]

        if configured:
            servers.extend(configured)

    # Fallback to individual settings
    if not servers:
        for attr in ("ad_server", "ad_host", "ad_dc1", "ad_dc2"):
            value = getattr(settings, attr, None)

            if value:
                if isinstance(value, str):
                    servers.append(value)

    # Remove duplicates while preserving order
    result = []
    seen = set()

    for server in servers:
        if server not in seen:
            result.append(server)
            seen.add(server)

    return result


def _escape_ldap_filter(value: str) -> str:
    """
    Escape LDAP filter special characters.
    """
    return (
        value.replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _normalize_username(username: str) -> str:
    """
    Convert login name into AD UPN format.

    Examples:
        smtpusr
        smtpusr@muktopay.com
        MUKTOPAY\\smtpusr
    """

    username = username.strip()

    if "\\" in username:
        username = username.split("\\", 1)[1]

    if "@" not in username:
        username = f"{username}@muktopay.com"

    return username


def _normalize_dn(dn: str) -> str:
    return dn.strip().lower()


def _close_connection(conn: Optional[Connection]):
    if conn:
        try:
            if conn.bound:
                conn.unbind()
            else:
                conn.unbind()
        except Exception:
            pass


def _get_role(groups):
    """
    Resolve application role from AD groups.

    Expected settings.role_map() format:

        {
            "CN=SMTP Admin,...": "SMTP Admin",
            "CN=Security Admin,...": "Security Admin",
            "CN=Read Only,...": "Read Only"
        }
    """

    try:
        role_map = settings.role_map()
    except Exception:
        role_map = {}

    normalized_groups = {
        _normalize_dn(group)
        for group in groups
    }

    for group_dn, role in role_map.items():
        if _normalize_dn(group_dn) in normalized_groups:
            return role

    return None


def authenticate_ad(username: str, password: str):
    """
    Authenticate an AD user using plain LDAP TCP/389.

    IMPORTANT:
    - No STARTTLS
    - No LDAPS
    - No certificate
    - No SSL
    - Requires AD to permit the authentication method being used.

    Returns:
        {
            "username": "...",
            "display_name": "...",
            "email": "...",
            "dn": "...",
            "groups": [...],
            "role": "..."
        }

    Returns None when authentication/authorization fails.
    """

    if not username or not password:
        logger.warning("AD authentication rejected: empty username/password")
        return None

    username = _normalize_username(username)

    ad_servers = _get_ad_servers()

    if not ad_servers:
        logger.error("No AD servers configured")
        return None

    # AD service account used to search the directory.
    service_username = getattr(settings, "ad_service_username", None)
    service_password = getattr(settings, "ad_service_password", None)

    if not service_username or not service_password:
        logger.error(
            "AD service account is not configured"
        )
        return None

    # Required SMTP authorization group.
    required_group_dn = getattr(
        settings,
        "ad_group_dn",
        None
    )

    for ad_host in ad_servers:

        search_conn = None
        user_conn = None

        try:
            logger.debug(
                "Trying AD authentication against %s user=%s",
                ad_host,
                username
            )

            # ---------------------------------------------------------
            # 1. LDAP SERVER
            # ---------------------------------------------------------
            server = Server(
                ad_host,
                port=389,
                use_ssl=False,
                get_info=ALL,
                connect_timeout=5
            )

            # ---------------------------------------------------------
            # 2. SERVICE ACCOUNT CONNECTION
            #
            # Used to locate the user's DN and group membership.
            # ---------------------------------------------------------
            search_conn = Connection(
                server,
                user=service_username,
                password=service_password,
                authentication=NTLM,
                auto_bind=False,
                raise_exceptions=True
            )

            search_conn.open()

            # IMPORTANT:
            # No STARTTLS here.
            # No certificate.
            search_conn.bind()

            logger.debug(
                "AD service account bind successful against %s",
                ad_host
            )

            # ---------------------------------------------------------
            # 3. SEARCH USER
            # ---------------------------------------------------------
            escaped_username = _escape_ldap_filter(username)

            search_filter = (
                f"(&(objectClass=user)"
                f"(userPrincipalName={escaped_username}))"
            )

            search_conn.search(
                search_base="DC=muktopay,DC=com",
                search_filter=search_filter,
                attributes=[
                    "distinguishedName",
                    "displayName",
                    "mail",
                    "sAMAccountName",
                    "userPrincipalName",
                    "memberOf"
                ]
            )

            if not search_conn.entries:
                logger.warning(
                    "AD user not found: user=%s DC=%s",
                    username,
                    ad_host
                )

                _close_connection(search_conn)
                search_conn = None
                continue

            entry = search_conn.entries[0]

            user_dn = str(entry.distinguishedName.value)

            display_name = (
                str(entry.displayName.value)
                if entry.displayName.value
                else username
            )

            email = (
                str(entry.mail.value)
                if entry.mail.value
                else username
            )

            sam_account_name = (
                str(entry.sAMAccountName.value)
                if entry.sAMAccountName.value
                else ""
            )

            # ---------------------------------------------------------
            # 4. DIRECT GROUP MEMBERSHIP
            # ---------------------------------------------------------
            groups = []

            try:
                if entry.memberOf.value:
                    groups = list(entry.memberOf.values)
            except Exception:
                groups = []

            # ---------------------------------------------------------
            # 5. REQUIRED SMTP GROUP CHECK
            # ---------------------------------------------------------
            if required_group_dn:

                required_group_normalized = _normalize_dn(
                    required_group_dn
                )

                user_groups_normalized = {
                    _normalize_dn(group)
                    for group in groups
                }

                if required_group_normalized not in user_groups_normalized:

                    logger.warning(
                        "AD user is not authorized for SMTP portal: "
                        "user=%s required_group=%s DC=%s",
                        username,
                        required_group_dn,
                        ad_host
                    )

                    _close_connection(search_conn)
                    search_conn = None
                    continue

            # ---------------------------------------------------------
            # 6. RESOLVE APPLICATION ROLE
            # ---------------------------------------------------------
            role = _get_role(groups)

            if not role:
                logger.warning(
                    "AD user authenticated but has no application role: "
                    "user=%s DC=%s",
                    username,
                    ad_host
                )

                _close_connection(search_conn)
                search_conn = None
                continue

            # Search connection no longer required.
            _close_connection(search_conn)
            search_conn = None

            # ---------------------------------------------------------
            # 7. AUTHENTICATE USER
            # ---------------------------------------------------------
            #
            # Plain LDAP authentication:
            #
            # ldap://DC:389
            #
            # No STARTTLS.
            # No certificate.
            #
            user_conn = Connection(
                server,
                user=username,
                password=password,
                authentication=NTLM,
                auto_bind=False,
                raise_exceptions=True
            )

            user_conn.open()

            if not user_conn.bind():

                logger.warning(
                    "AD user bind failed: user=%s DC=%s",
                    username,
                    ad_host
                )

                _close_connection(user_conn)
                user_conn = None
                continue

            logger.info(
                "AD authentication successful: user=%s DC=%s role=%s",
                username,
                ad_host,
                role
            )

            # ---------------------------------------------------------
            # 8. RETURN USER INFORMATION
            # ---------------------------------------------------------
            result = {
                "username": username,
                "sAMAccountName": sam_account_name,
                "display_name": display_name,
                "email": email,
                "dn": user_dn,
                "groups": groups,
                "role": role,
                "dc": ad_host
            }

            _close_connection(user_conn)

            return result

        except LDAPException as exc:

            logger.exception(
                "AD LDAP authentication error: "
                "user=%s DC=%s error=%s",
                username,
                ad_host,
                exc
            )

        except Exception as exc:

            logger.exception(
                "Unexpected AD authentication error: "
                "user=%s DC=%s error=%s",
                username,
                ad_host,
                exc
            )

        finally:

            _close_connection(search_conn)
            _close_connection(user_conn)

    logger.error(
        "AD authentication failed against all configured DCs: user=%s",
        username
    )

    return None