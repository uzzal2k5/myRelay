import ssl
import logging
#from ldap3 import Server, Connection, ALL, Tls
from ldap3 import Server, Connection, ALL
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
    Require proper TLS certificate validation.
    The AD CA certificate must be trusted by the OEL server.
    """
    return Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
    )


def authenticate_ad(username: str, password: str):
    """
    Authenticate a portal user against on-prem Microsoft AD.

    Flow:
        1. Connect to AD DC using LDAPS.
        2. Bind using LDAP service account.
        3. Search for the user's DN and group membership.
        4. Verify membership in MP-SMTP-Users.
        5. Authenticate the actual user's password.
        6. Determine application RBAC role.
        7. Return authenticated user information.
    """

    if not username or not password:
        logger.warning("AD authentication rejected: username or password missing")
        return None

    username = username.strip()

    if not username:
        logger.warning("AD authentication rejected: empty username")
        return None

    # Convert username to UPN.
    # Example:
    #   shafiqul.islam
    #       ->
    #   shafiqul.islam@muktopay.com
    user_upn = (
        username
        if "@" in username
        else f"{username}@{settings.ad_domain}"
    ).strip().lower()
    logger.debug("AD authentication started: user=%s", user_upn)
    #tls_config = _get_tls_config()
    ad_servers = _get_ad_servers()
    logger.debug(
        "Configured AD servers: %s",
        ", ".join(ad_servers)
    )
    # Try DC01 first, then DC02.
    for ad_host in _get_ad_servers():

        search_conn = None
        user_conn = None
        logger.debug(
            "Attempting AD authentication against DC=%s port=%s",
            ad_host,
            settings.ad_ldap_port,
        )
        try:
            # ---------------------------------------------------------
            # 1. Create LDAPS server connection
            # ---------------------------------------------------------
            server = Server(
                ad_host,
                port=settings.ad_ldap_port,
                use_ssl=False,
                #tls=tls_config,
                get_info=ALL,
                connect_timeout=5,
            )
            logger.debug(
                "LDAPS Server object created successfully for DC=%s",
                ad_host,
            )
            # ---------------------------------------------------------
            # 2. Bind using service account
            # ---------------------------------------------------------
            logger.debug(
                "Binding to AD using service account=%s",
                settings.ad_bind_user,
            )
            search_conn = Connection(
                server,
                user=settings.ad_bind_user,
                password=settings.ad_bind_password,
                auto_bind=True,
                raise_exceptions=False,
            )
            logger.debug(
                "Service-account bind result: bound=%s result=%s",
                search_conn.bound,
                search_conn.result,
            )
            if not search_conn.bound:
                logger.error(
                    "AD service-account bind failed: DC=%s result=%s",
                    ad_host,
                    search_conn.result,
                )
                search_conn.unbind()
                search_conn = None
                continue

            # ---------------------------------------------------------
            # 3. Search the user
            # ---------------------------------------------------------
            safe_upn = _escape_ldap_filter(user_upn)

            search_filter = (
                "(&(objectClass=user)"
                f"(userPrincipalName={safe_upn}))"
            )
            logger.debug(
                "Searching AD: base_dn=%s filter=%s",
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
            logger.debug(
                "AD user search result: found=%s entries=%s result=%s",
                found,
                len(search_conn.entries),
                search_conn.result,
            )
            if not found or not search_conn.entries:
                logger.warning(
                    "AD user not found: user=%s base_dn=%s",
                    user_upn,
                    settings.ad_base_dn,
                )

                search_conn.unbind()
                search_conn = None
                return None

            entry = search_conn.entries[0]

            # ---------------------------------------------------------
            # 4. Get user's DN
            # ---------------------------------------------------------
            user_dn = str(entry.distinguishedName.value)
            logger.debug(
                "AD user found: user=%s DN=%s",
                user_upn,
                user_dn,
            )
            # ---------------------------------------------------------
            # 5. Get direct AD group membership
            # ---------------------------------------------------------
            groups = set()

            if hasattr(entry, "memberOf") and entry.memberOf:
                groups = {
                    str(group).strip()
                    for group in entry.memberOf.values
                    if str(group).strip()
                }
            logger.debug(
                "AD groups found for user=%s count=%d",
                user_upn,
                len(groups),
            )
            for group in sorted(groups):
                logger.debug(
                    "AD group membership: user=%s group=%s",
                    user_upn,
                    group,
            )
            # ---------------------------------------------------------
            # 6. Check mandatory SMTP user group
            # ---------------------------------------------------------
            required_group = settings.ad_group_dn.strip()
            logger.debug(
                "Required SMTP group DN=%s",
                required_group,
            )
            if required_group and required_group not in groups:
                logger.warning(
                    "SMTP authentication denied: user=%s is NOT a member "
                    "of required group=%s",
                    user_upn,
                    required_group,
                )
                search_conn.unbind()
                search_conn = None
                return None
            logger.debug(
                "SMTP group membership validated: user=%s",
                user_upn,
            )
            # Search connection is no longer required.
            search_conn.unbind()
            search_conn = None

            # ---------------------------------------------------------
            # 7. Validate actual user's password
            # ---------------------------------------------------------
            logger.debug(
                "Validating user password through AD: user=%s DC=%s",
                user_upn,
                ad_host,
            )
            user_conn = Connection(
                server,
                user=user_upn,
                password=password,
                auto_bind=True,
                raise_exceptions=False,
            )
            logger.debug(
                "User bind result: user=%s bound=%s result=%s",
                user_upn,
                user_conn.bound,
                user_conn.result,
            )
            if not user_conn.bound:
                logger.warning(
                    "AD user authentication failed: user=%s result=%s",
                    user_upn,
                    user_conn.result,
                )
                user_conn.unbind()
                user_conn = None
                return None

            logger.debug(
                "AD user password authentication successful: user=%s",
                user_upn,
            )
            user_conn.unbind()
            user_conn = None

            # ---------------------------------------------------------
            # 8. Determine application role
            # ---------------------------------------------------------
            role = "read_only"

            role_map = settings.role_map()

            if groups & role_map["security_admin"]:
                role = "security_admin"

            elif groups & role_map["smtp_admin"]:
                role = "smtp_admin"

            elif groups & role_map["read_only"]:
                role = "read_only"
            logger.debug(
                "Resolved application role: user=%s role=%s",
                user_upn,
                role,
            )
            # ---------------------------------------------------------
            # 9. Successful authentication
            # ---------------------------------------------------------
            logger.info(
                "AD authentication successful: user=%s role=%s DC=%s",
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

        #except (LDAPException, OSError, ssl.SSLError) as exc:

        except (LDAPException, OSError) as exc:
            # Current DC failed.
            # Try the next configured DC.
            logger.exception(
                "AD authentication error: user=%s DC=%s error=%s",
                user_upn,
                ad_host,
                exc,
            )
            continue

        except Exception as exc:

            logger.exception(
                "Unexpected AD authentication error: user=%s DC=%s error=%s",
                user_upn,
                ad_host,
                exc,
            )

            continue

        finally:
            if search_conn is not None:
                try:
                    search_conn.unbind()
                except Exception:
                    pass

            if user_conn is not None:
                try:
                    user_conn.unbind()
                except Exception:
                    pass
    logger.error(
        "AD authentication failed against all configured DCs: user=%s",
        user_upn,
    )
    # All configured DCs failed.
    return None