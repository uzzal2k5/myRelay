from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SMTP Admin"
    auth_mode: str = "ad"
    session_secret: str = "CHANGE_ME_TO_A_LONG_RANDOM_VALUE"
    session_timeout_minutes: int = 30

    # Active Directory
    ad_server_1: str = "gzvwmpudm01.muktopay.com"
    ad_server_2: str = "gzvwmpudm02.muktopay.com"
    ad_ldap_port: int = 636

    ad_use_ldaps: bool = True
    ad_use_starttls: bool = True

    ad_verify_cert: bool = True
    ad_ca_certs_file: str = ""

    ad_domain: str = "muktopay.com"
    ad_base_dn: str = "DC=muktopay,DC=com"

    ad_bind_user: str = "svc_smtp_dashboard@muktopay.com"
    ad_bind_password: str = ""

    ad_group_dn: str = (
        "CN=MP-SMTP-Users,OU=App Integration Group,OU=Muktopay,DC=muktopay,DC=com"
    )

    # Redis
    redis_host: str = "127.0.0.1"
    redis_port: int = 6379
    redis_db: int = 1
    redis_password: str = ""
    # SSL/TLS Cert Location
    certificate_path: str = "/etc/postfix/tls"
    private_key_path: str = "/etc/postfix/tls"
    # Postfix
    postfix_policy_path: str = "/etc/postfix"
    postfix_backup_path: str = "/etc/postfix/backup"

    # Audit
    audit_log_path: str = "/var/log/smtp-admin/audit.log"

    # RBAC
    role_smtp_admins: str = (
        #"CN=MP-SMTP-Admins,OU=Groups,DC=muktopay,DC=com"
        "CN=MP-SMTP-Admins,OU=App Integration Group,OU=Muktopay,DC=muktopay,DC=com"
    )

    role_security_admins: str = (
        "CN=MP-SMTP-Security-Admins,OU=App Integration Group,OU=Muktopay,DC=muktopay,DC=com"
    )

    role_read_only: str = (
        "CN=MP-SMTP-ReadOnly,OU=App Integration Group,OU=Muktopay,DC=muktopay,DC=com"
    )
    def role_map(self) -> dict:
        """
        Maps each application role to the set of AD group DNs that grant
        it. Each setting above holds a single DN today; this returns
        single-item sets so ad.py's set-intersection logic works
        unchanged if a role is ever backed by more than one group later
        (e.g. role_smtp_admins becoming a comma-separated list).
        """
        return {
            "security_admin": {self.role_security_admins},
            "smtp_admin": {self.role_smtp_admins},
            "read_only": {self.role_read_only},
        }
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()