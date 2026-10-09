
import ssl
import logging
from typing import Optional

from ldap3 import ALL, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException

from ..config import settings

logger = logging.getLogger(__name__)


def _get_ad_servers():
    """
    Return configured AD Domain Controllers in priority order.
    DC01 is tried first, then DC02.
    """
    servers = []

    for host in (settings.ad_server_1, settings.ad_server_2):
        if host:
            host = host.strip()
            if host and host not in servers:
                servers.append(host)

    return servers


def _escape_ldap_filter(value: str) -> str:
    """
    Escape LDAP filter special characters according to RFC 4515.
    """
    return (
        value
        .replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _get_tls_config() -> Tls:
    """
    Configure LDAPS TLS.

    Certificate verification is enabled by default.

    If the AD CA certificate is installed in the OEL system trust store,
    ad_ca_certs_file may remain empty and the system CA bundle will be used.

    Certificate verification may only be explicitly disabled through
    ad_verify_cert=false. This should NOT be used on production systems.
    """
    verify = getattr(settings, "ad_verify_cert", True)
    ca_file = getattr(settings, "ad_ca_certs_file", None) or None

    if not verify:
        logger.warning(
            "AD TLS certificate verification is DISABLED "
            "(ad_verify_cert=false). "
            "This should only be used in a non-production environment."
        )

    return Tls(
        validate=ssl.CERT_REQUIRED if verify else ssl.CERT_NONE,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_file=ca_file,
    )


def _resolve_role(groups_lower: set, role_map: dict) -> Optional[str]:
    """
    Resolve the SMTP Admin Portal RBAC role from AD group membership.

    Portal authorization groups:

        MP-SMTP-Security-Admins -> security_admin
        MP-SMTP-Admins          -> smtp_admin
        MP-SMTP-ReadOnly        -> read_only

    MP-SMTP-Users is intentionally NOT checked here.

    MP-SMTP-Users is reserved for SMTP client authentication and must
    not grant access to the SMTP Admin Portal.

    Returns:
        security_admin
        smtp_admin
        read_only
        None if the user is not a member of any portal RBAC group.
    """
    for role in ("security_admin", "smtp_admin", "read_only"):
        role_dns = {
            str(dn).strip().lower()
            for dn in role_map.get(role, set())
            if str(dn).strip()
        }

        if groups_lower & role_dns:
            return role

    return None


def authenticate_ad(username: str, password: str):
    """
    Authenticate an SMTP Admin Portal user against on-prem Microsoft AD.

    Authentication and authorization flow:

        1. Connect to an AD Domain Controller using LDAPS.
        2. Bind using the configured LDAP service account.
        3. Search for the requested AD user.
        4. Read the user's direct AD group memberships.
        5. Resolve the SMTP Admin Portal RBAC role.
        6. Deny access if the user is not in any portal RBAC group.
        7. Authenticate the actual user's password against AD.
        8. Return authenticated user information and role.

    Portal RBAC groups:

        MP-SMTP-Security-Admins -> security_admin
        MP-SMTP-Admins          -> smtp_admin
        MP-SMTP-ReadOnly        -> read_only

    Important:
        MP-SMTP-Users is NOT used for Admin Portal authorization.
        It is reserved for SMTP client authentication to Postfix.
    """

    if not username or not password:
        logger.warning(
            "AD authentication rejected: username or password missing"
        )
        return None

    username = username.strip()

    if not username:
        logger.warning(
            "AD authentication rejected: empty username"
        )
        return None

    # Convert username to UPN.
    #
    # Example:
    #   shafiqul.islam
    # becomes:
    #   shafiqul.islam@muktopay.com
    if "@" in username:
        user_upn = username.strip().lower()
    else:
        domain = (settings.ad_domain or "").strip()

        if not domain:
            logger.error(
                "AD authentication cannot proceed: '%s' has no '@domain' "
                "and settings.ad_domain is not configured.",
                username,
            )
            return None

        user_upn = f"{username}@{domain}".strip().lower()

    sam_account_name = user_upn.split("@", 1)[0]

    logger.debug(
        "AD authentication started: user=%s",
        user_upn,
    )

    ad_servers = _get_ad_servers()

    if not ad_servers:
        logger.error(
            "AD authentication cannot proceed: "
            "no AD servers configured."
        )
        return None

    logger.debug(
        "Configured AD servers: %s",
        ", ".join(ad_servers),
    )

    tls_config = _get_tls_config()
    ldap_port = getattr(settings, "ad_ldap_port", None) or 636

    for ad_host in ad_servers:

        search_conn = None
        user_conn = None

        logger.debug(
            "Attempting AD authentication against DC=%s port=%s",
            ad_host,
            ldap_port,
        )

        try:
            # ---------------------------------------------------------
            # 1. Create LDAPS server connection
            # ---------------------------------------------------------
            server = Server(
                ad_host,
                port=ldap_port,
                use_ssl=True,
                tls=tls_config,
                get_info=ALL,
                connect_timeout=5,
            )

            logger.debug(
                "LDAPS Server object created for DC=%s",
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
            safe_sam = _escape_ldap_filter(sam_account_name)

            search_filter = (
                "(&(objectClass=user)"
                f"(|(userPrincipalName={safe_upn})"
                f"(sAMAccountName={safe_sam})))"
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

            if len(search_conn.entries) > 1:
                logger.error(
                    "AD search matched more than one account for user=%s - "
                    "refusing to authenticate against an ambiguous match.",
                    user_upn,
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

            groups_lower = {
                group.lower()
                for group in groups
            }

            logger.debug(
                "AD groups found for user=%s count=%d",
                user_upn,
                len(groups),
            )

            # ---------------------------------------------------------
            # 6. Resolve Admin Portal RBAC role
            # ---------------------------------------------------------
            role = _resolve_role(
                groups_lower,
                settings.role_map(),
            )

            if role is None:
                logger.warning(
                    "SMTP Admin Portal access denied: user=%s is not a "
                    "member of any configured portal RBAC group. "
                    "Required groups: security_admin=%s, smtp_admin=%s, "
                    "read_only=%s",
                    user_upn,
                    settings.role_security_admins,
                    settings.role_smtp_admins,
                    settings.role_read_only,
                )

                search_conn.unbind()
                search_conn = None
                return None

            logger.info(
                "SMTP Admin Portal RBAC authorized: user=%s role=%s",
                user_upn,
                role,
            )

            # Search connection is no longer required.
            search_conn.unbind()
            search_conn = None

            # ---------------------------------------------------------
            # 7. Validate the actual user's password
            # ---------------------------------------------------------
            logger.debug(
                "Validating user password through AD: "
                "user=%s DC=%s",
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
                    "AD user authentication failed: "
                    "user=%s result=%s",
                    user_upn,
                    user_conn.result,
                )

                user_conn.unbind()
                user_conn = None
                return None

            logger.info(
                "AD user password authentication successful: user=%s",
                user_upn,
            )

            user_conn.unbind()
            user_conn = None

            # ---------------------------------------------------------
            # 8. Successful authentication
            # ---------------------------------------------------------
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

        except (LDAPException, OSError, ssl.SSLError) as exc:
            # Current DC failed - try the next configured DC.
            logger.exception(
                "AD authentication error: user=%s DC=%s error=%s",
                user_upn,
                ad_host,
                exc,
            )
            continue

        except Exception as exc:
            logger.exception(
                "Unexpected AD authentication error: "
                "user=%s DC=%s error=%s",
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

    return None

