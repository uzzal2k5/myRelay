from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import os
import re
import shutil
import subprocess
import logging


# Application logger
logger = logging.getLogger(__name__)

# Postfix Service Class
class PostfixService:
    """
    Manage the existing Postfix configuration and existing map files.

    IMPORTANT DESIGN RULES
    ----------------------
    1. Do not create a new /etc/postfix/policy directory.
    2. Use the existing /etc/postfix/ip-management directory.
    3. Discover map files from the active Postfix configuration.
    4. Do not require hard-coded map filenames.
    5. Only allow files under /etc/postfix.
    6. Do not allow the application to modify arbitrary Postfix files.
    7. Only configured Postfix maps can be modified.
    8. Create a backup before every modification.
    9. Rebuild database maps only when required.
    10. Validate Postfix configuration before reload.
    11. Use smtp-admin-postfix-helper for privileged operations.
    """

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------

    POSTFIX_ROOT = Path("/etc/postfix")

    MAP_DIRECTORY = (
        POSTFIX_ROOT / "ip-management"
    )

    BACKUP_DIRECTORY = (
        POSTFIX_ROOT / "backup"
    )

    HELPER = (
        "/usr/local/sbin/"
        "smtp-admin-postfix-helper"
    )

    # Maximum source-map size accepted by the UI.
    MAX_MAP_SIZE = 20 * 1024 * 1024

    # ------------------------------------------------------------------
    # Supported Postfix map backends
    # ------------------------------------------------------------------

    SUPPORTED_BACKENDS = {
        "hash",
        "btree",
        "lmdb",
        "cdb",
        "pcre",
        "regexp",
        "texthash",
        "dbm",
        "sdbm",
    }

    # Backends which normally require postmap/database generation.
    DATABASE_BACKENDS = {
        "hash",
        "btree",
        "cdb",
        "dbm",
        "sdbm",
        "lmdb",
    }

    # Direct text/regular-expression maps.
    TEXT_BACKENDS = {
        "pcre",
        "regexp",
        "texthash",
    }

    # ------------------------------------------------------------------
    # Postfix configuration parameters which can contain map specs
    # ------------------------------------------------------------------

    MAP_CONFIG_KEYS = [
        "access_maps",
        "alias_maps",
        "canonical_maps",
        "sender_canonical_maps",
        "recipient_canonical_maps",
        "relocated_maps",
        "transport_maps",
        "virtual_alias_maps",
        "virtual_alias_domains",
        "virtual_mailbox_maps",
        "virtual_mailbox_domains",
        "virtual_gid_maps",
        "virtual_uid_maps",
        "local_recipient_maps",
        "smtpd_sender_login_maps",

        "smtpd_sender_restrictions",
        "smtpd_recipient_restrictions",
        "smtpd_client_restrictions",
        "smtpd_helo_restrictions",
        "smtpd_data_restrictions",
        "smtpd_end_of_data_restrictions",
        "smtpd_relay_restrictions",
        "smtpd_etrn_restrictions",

        "smtpd_milter_maps",

        "header_checks",
        "mime_header_checks",
        "nested_header_checks",
        "body_checks",

        "smtp_header_checks",
        "smtp_mime_header_checks",
        "smtp_nested_header_checks",
        "smtp_body_checks",
    ]

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    def __init__(
        self,
        map_directory: Optional[str] = None,
        backup_directory: Optional[str] = None,
    ):
        self.map_directory = Path(
            map_directory
            or self.MAP_DIRECTORY
        ).resolve()

        self.backup_directory = Path(
            backup_directory
            or self.BACKUP_DIRECTORY
        ).resolve()

        # Create backup directory only.
        #
        # We deliberately do NOT create the map directory because
        # the application must manage existing Postfix maps only.
        self.backup_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    # ==================================================================
    # Command execution
    # ==================================================================

    def _run(
        self,
        args: List[str],
        timeout: int = 15,
    ):
        """
        Execute a system command.

        check=False is intentional because callers inspect
        returncode themselves.
        """

        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    # ==================================================================
    # Postfix configuration
    # ==================================================================

    def postconf(
        self,
        key: Optional[str] = None,
    ) -> str:
        """
        Get Postfix configuration.

        Examples:

            postconf()

            postconf("smtpd_client_restrictions")
        """

        args = [
            "/usr/sbin/postconf"
        ]

        if key:
            args.extend(
                [
                    "-h",
                    key,
                ]
            )

        result = self._run(args)

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip()
                or "postconf failed"
            )

        return result.stdout.strip()

    def show_effective_config(self) -> str:
        """
        Return the effective non-default Postfix configuration.
        """

        result = self._run(
            [
                "/usr/sbin/postconf",
                "-n",
            ]
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip()
                or "postfix configuration query failed"
            )

        return result.stdout

    # ==================================================================
    # Postfix Submission Configuration
    # ==================================================================
    def get_submission_service(self) -> str:
        """
        Get the Postfix submission service definition.

        This reads the master.cf service entry using:
            postconf -M submission/inet

        Note:
            Service-specific -o overrides from master.cf are not included
            by postconf -M. They must be read separately from master.cf.
        """
        try:
            result = subprocess.run(
                ["postconf", "-M", "submission/inet"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            return {
                "success": result.returncode == 0,
                "command": "postconf -M submission/inet",
                "output": result.stdout.strip(),
                "error": result.stderr.strip(),
                "returncode": result.returncode,
            }

        except Exception as exc:
            logger.exception(
                "Failed to query Postfix submission service"
            )

            return {
                "success": False,
                "command": "postconf -M submission/inet",
                "output": "",
                "error": str(exc),
                "returncode": -1,
            }

    def get_submission_restrictions(self) -> str:
        """
        Validate submission service and its service-specific overrides.

        postconf -M submission/inet shows the master.cf service definition,
        while the -o parameters are stored in the master.cf continuation lines.
        """

        try:
            result = subprocess.run(
                [
                    "awk",
                    r"""
                    /^submission[[:space:]]+inet[[:space:]]/ {
                        found=1
                        print
                        next
                    }

                    found && /^[[:space:]]+-o[[:space:]]/ {
                        print
                        next
                    }

                    found && !/^[[:space:]]+-o[[:space:]]/ {
                        exit
                    }
                    """,
                    "/etc/postfix/master.cf",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            output = result.stdout.strip()

            return {
                "success": result.returncode == 0,
                "submission_configured": bool(output),
                "output": output,
                "error": result.stderr.strip(),
                "returncode": result.returncode,
            }

        except Exception as exc:
            logger.exception(
                "Failed to validate Postfix submission configuration"
            )

            return {
                "success": False,
                "submission_configured": False,
                "output": "",
                "error": str(exc),
                "returncode": -1,
            }

    def view_submission_restrictions(self) -> dict:
        """
        Read Postfix submission restriction maps and return
        a clean, human-readable configuration for the Admin Portal.
        """

        POLICY_DIR = "/etc/postfix/ip-management"

        MAP_FILES = {
            "allowed_ips": "allowed_ips",
            "blocked_ips": "blocked_ips",
            "denied_ips": "denied_ips",
            "allowed_recipient_domains": "allowed_recipient_domains",
            "rejected_recipient_domains": "rejected_recipient_domains",
            "restricted_recipient_domains": "restricted_recipient_domains",
        }

        def read_map(filename):
            """
            Read a Postfix map file.

            Supports formats such as:

                172.17.65.11 OK
                172.17.65.12 OK

            or:

                172.17.65.11
                172.17.65.12
            """

            path = os.path.join(POLICY_DIR, filename)

            if not os.path.isfile(path):
                return []

            entries = []

            try:
                with open(path, "r", encoding="utf-8") as file:
                    for line in file:
                        line = line.strip()

                        # Ignore empty lines
                        if not line:
                            continue

                        # Ignore comments
                        if line.startswith("#"):
                            continue

                        # Remove inline comments
                        line = line.split("#", 1)[0].strip()

                        if not line:
                            continue

                        # Postfix map format:
                        # key value
                        parts = line.split(None, 1)

                        key = parts[0].strip()

                        if key:
                            entries.append(key)

            except PermissionError:
                logger.error(
                    "Permission denied while reading Postfix map: %s",
                    path,
                )

            except Exception:
                logger.exception(
                    "Failed to read Postfix map: %s",
                    path,
                )

            return sorted(set(entries))

        # Format Submission
        def format_submission_restrictions(config):
            """
            Convert submission configuration dictionary
            into a human-readable multiline text.
            """

            lines = []

            lines.append("SMTP SUBMISSION CONFIGURATION")
            lines.append("=" * 60)

            # Status
            status = config.get("status", {})

            lines.append("")
            lines.append("STATUS")
            lines.append("-" * 60)
            lines.append(
                f"Overall Status       : {status.get('overall', 'Unknown')}"
            )
            lines.append(
                f"Configuration Loaded : "
                f"{'Yes' if status.get('configuration_loaded') else 'No'}"
            )

            # Client Access
            client = config.get("client_access", {})

            lines.append("")
            lines.append("CLIENT ACCESS CONTROL")
            lines.append("-" * 60)

            allowed = client.get("allowed", {})
            lines.append(
                f"Allowed IP Addresses : {allowed.get('count', 0)}"
            )

            for item in allowed.get("items", []):
                lines.append(f"  + {item}")

            blocked = client.get("blocked", {})
            lines.append(
                f"Blocked IP Addresses : {blocked.get('count', 0)}"
            )

            for item in blocked.get("items", []):
                lines.append(f"  - {item}")

            denied = client.get("denied", {})
            lines.append(
                f"Denied IP Addresses  : {denied.get('count', 0)}"
            )

            for item in denied.get("items", []):
                lines.append(f"  ! {item}")

            # Recipient Domains
            domains = config.get("recipient_domains", {})

            lines.append("")
            lines.append("RECIPIENT DOMAIN CONTROL")
            lines.append("-" * 60)

            allowed_domains = domains.get("allowed", {})
            lines.append(
                f"Allowed Domains      : "
                f"{allowed_domains.get('count', 0)}"
            )

            for item in allowed_domains.get("items", []):
                lines.append(f"  + {item}")

            rejected_domains = domains.get("rejected", {})
            lines.append(
                f"Rejected Domains     : "
                f"{rejected_domains.get('count', 0)}"
            )

            for item in rejected_domains.get("items", []):
                lines.append(f"  - {item}")

            restricted_domains = domains.get("restricted", {})
            lines.append(
                f"Restricted Domains   : "
                f"{restricted_domains.get('count', 0)}"
            )

            for item in restricted_domains.get("items", []):
                lines.append(f"  ! {item}")

            # Summary
            summary = config.get("summary", {})

            lines.append("")
            lines.append("SUMMARY")
            lines.append("-" * 60)

            lines.append(
                f"Allowed IPs          : "
                f"{summary.get('allowed_ips', 0)}"
            )
            lines.append(
                f"Blocked IPs          : "
                f"{summary.get('blocked_ips', 0)}"
            )
            lines.append(
                f"Denied IPs           : "
                f"{summary.get('denied_ips', 0)}"
            )
            lines.append(
                f"Allowed Domains      : "
                f"{summary.get('allowed_recipient_domains', 0)}"
            )
            lines.append(
                f"Rejected Domains     : "
                f"{summary.get('rejected_recipient_domains', 0)}"
            )
            lines.append(
                f"Restricted Domains   : "
                f"{summary.get('restricted_recipient_domains', 0)}"
            )

            return "\n".join(lines)




        # ---------------------------------------------------------
        # Read all Postfix policy maps
        # ---------------------------------------------------------

        policies = {}

        for policy_name, filename in MAP_FILES.items():
            policies[policy_name] = read_map(filename)

        # ---------------------------------------------------------
        # Prepare friendly display structure
        # ---------------------------------------------------------

        return {
            "title": "SMTP Submission Configuration",

            "status": {
                "overall": "Active",
                "configuration_loaded": True,
            },

            "client_access": {
                "title": "Client Access Control",

                "allowed": {
                    "label": "Allowed IP Addresses",
                    "count": len(policies["allowed_ips"]),
                    "items": policies["allowed_ips"],
                },

                "blocked": {
                    "label": "Blocked IP Addresses",
                    "count": len(policies["blocked_ips"]),
                    "items": policies["blocked_ips"],
                },

                "denied": {
                    "label": "Denied IP Addresses",
                    "count": len(policies["denied_ips"]),
                    "items": policies["denied_ips"],
                },
            },

            "recipient_domains": {
                "title": "Recipient Domain Control",

                "allowed": {
                    "label": "Allowed Recipient Domains",
                    "count": len(
                        policies["allowed_recipient_domains"]
                    ),
                    "items": policies[
                        "allowed_recipient_domains"
                    ],
                },

                "rejected": {
                    "label": "Rejected Recipient Domains",
                    "count": len(
                        policies["rejected_recipient_domains"]
                    ),
                    "items": policies[
                        "rejected_recipient_domains"
                    ],
                },

                "restricted": {
                    "label": "Restricted Recipient Domains",
                    "count": len(
                        policies["restricted_recipient_domains"]
                    ),
                    "items": policies[
                        "restricted_recipient_domains"
                    ],
                },
            },

            "summary": {
                "allowed_ips": len(policies["allowed_ips"]),
                "blocked_ips": len(policies["blocked_ips"]),
                "denied_ips": len(policies["denied_ips"]),
                "allowed_recipient_domains": len(
                    policies["allowed_recipient_domains"]
                ),
                "rejected_recipient_domains": len(
                    policies["rejected_recipient_domains"]
                ),
                "restricted_recipient_domains": len(
                    policies["restricted_recipient_domains"]
                ),
            },
        }


    # ==================================================================
    # Postfix helper operations
    # ==================================================================

    def check(self):
        """
        Validate Postfix configuration using the existing helper.
        """

        return self._run(
            [
                "sudo",
                self.HELPER,
                "check",
            ]
        )

    def reload(self):
        """
        Reload Postfix using the existing helper.
        """

        return self._run(
            [
                "sudo",
                self.HELPER,
                "reload",
            ]
        )

    def postmap(
        self,
        path: str,
    ):
        """
        Rebuild a database-backed Postfix map.
        """

        return self._run(
            [
                "sudo",
                self.HELPER,
                "postmap",
                path,
            ],
            timeout=30,
        )

    # ==================================================================
    # Path validation
    # ==================================================================

    def _validated_path(
        self,
        path: str,
    ) -> Path:
        """
        Validate a Postfix file path.

        Requirements:
          - absolute path
          - inside /etc/postfix
          - not inside /etc/postfix/backup
          - no path traversal outside /etc/postfix
        """

        if not path:
            raise ValueError(
                "Map path is required"
            )

        raw = Path(
            str(path)
        )

        if not raw.is_absolute():
            raise ValueError(
                "Map path must be absolute"
            )

        try:
            resolved = raw.resolve(
                strict=False
            )

            postfix_root = (
                self.POSTFIX_ROOT.resolve()
            )

            backup_root = (
                self.backup_directory.resolve()
            )

        except (
            OSError,
            RuntimeError,
        ) as exc:
            raise ValueError(
                f"Unable to resolve map path: {exc}"
            )

        # Must be below /etc/postfix.
        try:
            resolved.relative_to(
                postfix_root
            )

        except ValueError:
            raise ValueError(
                "Map path must be under /etc/postfix"
            )

        # /etc/postfix itself is not a map.
        if resolved == postfix_root:
            raise ValueError(
                "Map path cannot be /etc/postfix"
            )

        # Never permit backup files to be treated as maps.
        try:
            resolved.relative_to(
                backup_root
            )

        except ValueError:
            pass

        else:
            raise ValueError(
                "Backup files cannot be managed "
                "as Postfix maps"
            )

        return resolved

    # ==================================================================
    # Map specification parsing
    # ==================================================================

    def parse_map_spec(
        self,
        map_spec: str,
    ) -> Optional[Dict]:
        """
        Parse a Postfix map specification.

        Examples:

            hash:/etc/postfix/ip-management/allowed_ips

            regexp:/etc/postfix/ip-management/blocked_ips

            pcre:/etc/postfix/ip-management/denied_ips
        """

        if not map_spec:
            return None

        spec = str(
            map_spec
        ).strip()

        if ":" not in spec:
            return None

        backend, path = (
            spec.split(":", 1)
        )

        backend = (
            backend.strip()
            .lower()
        )

        path = path.strip()

        if backend not in (
            self.SUPPORTED_BACKENDS
        ):
            return None

        if not path.startswith("/"):
            return None

        try:
            validated = (
                self._validated_path(
                    path
                )
            )

        except ValueError:
            return None

        return {
            "backend": backend,
            "path": str(validated),
            "spec": (
                f"{backend}:{validated}"
            ),
        }

    def map_source_path(
        self,
        map_spec: str,
    ) -> Optional[Path]:
        """
        Return source file path from a map specification.
        """

        parsed = self.parse_map_spec(
            map_spec
        )

        if not parsed:
            return None

        return Path(
            parsed["path"]
        )

    # ==================================================================
    # Extract map specifications
    # ==================================================================

    def _extract_map_specs(
        self,
        value: str,
    ) -> List[str]:
        """
        Extract map specifications from a Postfix parameter.

        Example:

            check_client_access
            hash:/etc/postfix/ip-management/allowed_ips

        returns:

            [
                "hash:/etc/postfix/ip-management/allowed_ips"
            ]
        """

        if not value:
            return []

        backends = sorted(
            self.SUPPORTED_BACKENDS,
            key=len,
            reverse=True,
        )

        backend_pattern = "|".join(
            re.escape(backend)
            for backend in backends
        )

        pattern = re.compile(
            rf"(?<![\w-])"
            rf"({backend_pattern})"
            rf":"
            rf"(/[^\s,;]+)"
        )

        results = []

        for match in pattern.finditer(
            value
        ):

            backend = (
                match.group(1)
            )

            path = (
                match.group(2)
            )

            spec = (
                f"{backend}:{path}"
            )

            if spec not in results:
                results.append(
                    spec
                )

        return results

    # ==================================================================
    # Discover configured maps
    # ==================================================================

    def discover_existing_maps(
        self,
    ) -> Dict[str, Dict]:
        """
        Backward-compatible method used by the existing UI.

        Discover only map files referenced by the active
        Postfix configuration.

        No filename allow-list is used.

        Therefore these real files can be discovered:

            allowed_ips
            allowed_recipient_domains
            blocked_ips
            denied_ips
            rejected_recipient_domains
            restricted_recipient_domains

        provided that Postfix actually references them.
        """

        found: Dict[
            str,
            Dict
        ] = {}

        for config_key in (
            self.MAP_CONFIG_KEYS
        ):

            try:
                value = self.postconf(
                    config_key
                )

            except Exception:
                continue

            if not value:
                continue

            specs = (
                self._extract_map_specs(
                    value
                )
            )

            for spec in specs:

                parsed = (
                    self.parse_map_spec(
                        spec
                    )
                )

                if not parsed:
                    continue

                path = Path(
                    parsed["path"]
                )

                path_string = str(
                    path
                )

                backend = (
                    parsed["backend"]
                )

                # ------------------------------------------------------
                # Database path
                # ------------------------------------------------------

                database = None

                if backend in {
                    "hash",
                    "btree",
                    "cdb",
                    "dbm",
                    "sdbm",
                }:

                    database = (
                        path.parent
                        / f"{path.name}.db"
                    )

                elif backend == "lmdb":

                    database = (
                        path.parent
                        / f"{path.name}.lmdb"
                    )

                # ------------------------------------------------------
                # File state
                # ------------------------------------------------------

                exists = (
                    path.exists()
                )

                is_file = (
                    exists
                    and path.is_file()
                )

                readable = (
                    is_file
                    and os.access(
                        path,
                        os.R_OK,
                    )
                )

                writable = (
                    is_file
                    and os.access(
                        path,
                        os.W_OK,
                    )
                )

                # ------------------------------------------------------
                # First reference
                # ------------------------------------------------------

                if path_string not in found:

                    found[path_string] = {
                        "name": path.name,

                        "path": path_string,

                        "backend": backend,

                        "spec": (
                            parsed["spec"]
                        ),

                        "config_key": (
                            config_key
                        ),

                        "config_keys": [
                            config_key
                        ],

                        "specs": [
                            parsed["spec"]
                        ],

                        "exists": exists,

                        "is_file": is_file,

                        "readable": readable,

                        "writable": writable,

                        "active": True,

                        "configured": True,

                        "directory": str(
                            path.parent
                        ),

                        "database": (
                            str(database)
                            if database
                            else None
                        ),

                        "database_exists": (
                            database.exists()
                            if database
                            else False
                        ),
                    }

                # ------------------------------------------------------
                # Same map referenced by multiple parameters
                # ------------------------------------------------------

                else:

                    existing = (
                        found[path_string]
                    )

                    if config_key not in (
                        existing[
                            "config_keys"
                        ]
                    ):

                        existing[
                            "config_keys"
                        ].append(
                            config_key
                        )

                    if parsed[
                        "spec"
                    ] not in (
                        existing[
                            "specs"
                        ]
                    ):

                        existing[
                            "specs"
                        ].append(
                            parsed["spec"]
                        )

        return found

    # ==================================================================
    # New naming alias
    # ==================================================================

    def discover_configured_maps(
        self,
    ) -> Dict[str, Dict]:
        """
        Alias for discover_existing_maps().
        """

        return (
            self.discover_existing_maps()
        )

    # ==================================================================
    # Discover existing files in ip-management
    # ==================================================================

    def discover_directory_maps(
        self,
        directory: Optional[str] = None,
    ) -> List[Dict]:
        """
        Discover existing source files in the
        /etc/postfix/ip-management directory.

        This does NOT mean that all files are active Postfix maps.

        The result indicates whether each file is configured.
        """

        directory_path = Path(
            directory
            or self.map_directory
        )

        directory_path = (
            self._validated_path(
                str(directory_path)
            )
        )

        if not directory_path.exists():
            return []

        if not directory_path.is_dir():
            return []

        configured = (
            self.discover_existing_maps()
        )

        results = []

        for path in sorted(
            directory_path.iterdir(),
            key=lambda p: p.name.lower(),
        ):

            if not path.is_file():
                continue

            # Ignore hidden temporary files.
            if path.name.startswith("."):
                continue

            # Generated database files are not source maps.
            if path.suffix in {
                ".db",
                ".lmdb",
            }:
                continue

            path_string = str(path)

            configured_entry = (
                configured.get(
                    path_string
                )
            )

            results.append({
                "name": path.name,

                "path": path_string,

                "exists": True,

                "is_file": True,

                "readable": os.access(
                    path,
                    os.R_OK,
                ),

                "writable": os.access(
                    path,
                    os.W_OK,
                ),

                "active": (
                    configured_entry
                    is not None
                ),

                "configured": (
                    configured_entry
                    is not None
                ),

                "backend": (
                    configured_entry[
                        "backend"
                    ]
                    if configured_entry
                    else None
                ),

                "config_key": (
                    configured_entry[
                        "config_key"
                    ]
                    if configured_entry
                    else None
                ),

                "config_keys": (
                    configured_entry[
                        "config_keys"
                    ]
                    if configured_entry
                    else []
                ),

                "spec": (
                    configured_entry[
                        "spec"
                    ]
                    if configured_entry
                    else None
                ),

                "specs": (
                    configured_entry[
                        "specs"
                    ]
                    if configured_entry
                    else []
                ),

                "database": (
                    configured_entry[
                        "database"
                    ]
                    if configured_entry
                    else None
                ),

                "database_exists": (
                    configured_entry[
                        "database_exists"
                    ]
                    if configured_entry
                    else False
                ),
            })

        return results

    # ==================================================================
    # Combined map discovery
    # ==================================================================

    def discover_maps(
        self,
    ) -> Dict:
        """
        Return a complete map discovery result for the UI.

        Includes:

          maps
              Currently configured Postfix maps.

          existing_files
              All source files under ip-management.

          unconfigured_files
              Existing files not currently referenced by Postfix.
        """

        configured = (
            self.discover_existing_maps()
        )

        existing_files = (
            self.discover_directory_maps()
        )

        configured_paths = set(
            configured.keys()
        )

        unconfigured_files = [
            item
            for item in existing_files
            if item["path"]
            not in configured_paths
        ]

        return {
            "success": True,

            "directory": str(
                self.map_directory
            ),

            "count": len(
                configured
            ),

            "configured_count": len(
                configured
            ),

            "existing_count": len(
                existing_files
            ),

            "unconfigured_count": len(
                unconfigured_files
            ),

            "maps": list(
                configured.values()
            ),

            "existing_files": (
                existing_files
            ),

            "unconfigured_files": (
                unconfigured_files
            ),

            "message": (
                "Postfix map discovery completed."
                if configured
                else
                "No map files are currently "
                "referenced by the active "
                "Postfix configuration."
            ),
        }

    # ==================================================================
    # Get one map
    # ==================================================================

    def get_map(
        self,
        path: str,
    ) -> Optional[Dict]:
        """
        Return configuration metadata for one active map.
        """

        validated = (
            self._validated_path(
                path
            )
        )

        maps = (
            self.discover_existing_maps()
        )

        return maps.get(
            str(validated)
        )

    # ==================================================================
    # Is configured map?
    # ==================================================================

    def is_configured_map(
        self,
        path: str,
    ) -> bool:
        """
        Return True only when the map is actually
        referenced by active Postfix configuration.
        """

        return (
            self.get_map(path)
            is not None
        )

    # ==================================================================
    # Read map
    # ==================================================================

    def read_map(
        self,
        path: str,
    ) -> List[str]:
        """
        Read an existing Postfix source map.
        """

        validated = (
            self._validated_path(
                path
            )
        )

        # Only active configured maps can be read
        # through the policy UI.
        if not self.is_configured_map(
            str(validated)
        ):
            raise ValueError(
                "The selected file is not "
                "referenced by the active "
                "Postfix configuration"
            )

        if not validated.exists():
            raise FileNotFoundError(
                f"Map file not found: {validated}"
            )

        if not validated.is_file():
            raise ValueError(
                "Map path is not a regular file"
            )

        size = validated.stat().st_size

        if size > self.MAX_MAP_SIZE:
            raise ValueError(
                "Map file is too large to read"
            )

        if not os.access(
            validated,
            os.R_OK,
        ):
            raise PermissionError(
                "Map file is not readable"
            )

        return validated.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()

    # ==================================================================
    # Backup
    # ==================================================================

    def backup(
        self,
        path: str,
    ) -> Optional[Path]:
        """
        Create a timestamped backup.
        """

        validated = (
            self._validated_path(
                path
            )
        )

        if not validated.exists():
            return None

        if not validated.is_file():
            raise ValueError(
                "Cannot backup a non-file"
            )

        timestamp = (
            datetime.now().strftime(
                "%Y%m%d-%H%M%S"
            )
        )

        backup_name = (
            f"{validated.name}."
            f"{timestamp}.bak"
        )

        destination = (
            self.backup_directory
            / backup_name
        )

        shutil.copy2(
            validated,
            destination,
        )

        return destination

    # ==================================================================
    # Write existing map
    # ==================================================================

    def write_existing_map(
        self,
        path: str,
        lines: List[str],
    ) -> Dict:
        """
        Safely replace an existing configured Postfix map.

        Process:

          1. Validate path.
          2. Confirm it is an active Postfix map.
          3. Create backup.
          4. Write temporary file.
          5. Atomically replace source file.
          6. Run postmap for database maps.
          7. Run postfix check.
          8. Reload Postfix.
          9. Roll back source + database on failure.
        """

        validated = (
            self._validated_path(
                path
            )
        )

        configured = (
            self.get_map(
                str(validated)
            )
        )

        if not configured:
            raise ValueError(
                "The selected file is not "
                "referenced by the active "
                "Postfix configuration"
            )

        if not validated.exists():
            raise FileNotFoundError(
                f"Existing map not found: {validated}"
            )

        if not validated.is_file():
            raise ValueError(
                "Map path is not a regular file"
            )

        backend = (
            configured["backend"]
        )

        # --------------------------------------------------------------
        # Backup
        # --------------------------------------------------------------

        backup = self.backup(
            str(validated)
        )

        # --------------------------------------------------------------
        # Clean input
        # --------------------------------------------------------------

        if lines is None:
            lines = []

        clean_lines = []

        for line in lines:

            if line is None:
                continue

            value = str(
                line
            ).rstrip()

            if value:
                clean_lines.append(
                    value
                )

        content = (
            "\n".join(
                clean_lines
            )
            + (
                "\n"
                if clean_lines
                else ""
            )
        )

        # --------------------------------------------------------------
        # Temporary file
        # --------------------------------------------------------------

        tmp = validated.with_name(
            f".{validated.name}"
            ".smtp-admin.tmp"
        )

        try:

            tmp.write_text(
                content,
                encoding="utf-8",
            )

            # Preserve original permissions.
            try:

                original_mode = (
                    validated.stat().st_mode
                    & 0o777
                )

                tmp.chmod(
                    original_mode
                )

            except OSError:

                tmp.chmod(
                    0o640
                )

            # Atomic replacement.
            tmp.replace(
                validated
            )

        except Exception:

            try:
                tmp.unlink(
                    missing_ok=True
                )
            except Exception:
                pass

            raise

        # --------------------------------------------------------------
        # Rebuild database map
        # --------------------------------------------------------------

        if backend in (
            self.DATABASE_BACKENDS
        ):

            result = self.postmap(
                str(validated)
            )

            if result.returncode != 0:

                self._rollback(
                    validated,
                    backup,
                    backend,
                )

                raise RuntimeError(
                    result.stderr.strip()
                    or "postmap failed"
                )

        # --------------------------------------------------------------
        # Validate Postfix configuration
        # --------------------------------------------------------------

        check_result = (
            self.check()
        )

        if check_result.returncode != 0:

            self._rollback(
                validated,
                backup,
                backend,
            )

            raise RuntimeError(
                check_result.stderr.strip()
                or
                "Postfix configuration "
                "validation failed"
            )

        # --------------------------------------------------------------
        # Reload Postfix
        # --------------------------------------------------------------

        reload_result = (
            self.reload()
        )

        if reload_result.returncode != 0:

            self._rollback(
                validated,
                backup,
                backend,
            )

            raise RuntimeError(
                reload_result.stderr.strip()
                or "Postfix reload failed"
            )

        return {
            "success": True,

            "path": str(
                validated
            ),

            "name": (
                validated.name
            ),

            "backend": backend,

            "backup": (
                str(backup)
                if backup
                else None
            ),

            "postmap": (
                backend
                in self.DATABASE_BACKENDS
            ),

            "reloaded": True,
        }

    # ==================================================================
    # Rollback
    # ==================================================================

    def _rollback(
        self,
        path: Path,
        backup: Optional[Path],
        backend: str,
    ) -> None:
        """
        Restore source map from backup.

        This method deliberately does not raise another exception
        because the original operation error is more useful to
        the caller.
        """

        if not backup:
            return

        try:

            shutil.copy2(
                backup,
                path,
            )

            if backend in (
                self.DATABASE_BACKENDS
            ):

                self.postmap(
                    str(path)
                )

        except Exception:
            pass

    # ==================================================================
    # Summary
    # ==================================================================

    def map_summary(
        self,
    ) -> Dict:
        """
        Return concise map information.
        """

        result = (
            self.discover_maps()
        )

        return {
            "success": result[
                "success"
            ],

            "directory": result[
                "directory"
            ],

            "count": result[
                "configured_count"
            ],

            "configured_count": result[
                "configured_count"
            ],

            "existing_count": result[
                "existing_count"
            ],

            "unconfigured_count": result[
                "unconfigured_count"
            ],

            "maps": result[
                "maps"
            ],

            "unconfigured_files": result[
                "unconfigured_files"
            ],

            "message": result[
                "message"
            ],
        }

