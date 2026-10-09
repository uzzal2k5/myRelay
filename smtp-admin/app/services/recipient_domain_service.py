from pathlib import Path
import os
import re
import shutil
from datetime import datetime
from typing import Dict, List, Optional


class RecipientDomainService:
    """
    Manage Postfix recipient-domain / recipient restrictions.

    UI representation:

        allowed:
            muktopay.com

        rejected:
            gmail.com

        restricted:
            ceo@muktopay.com

    Postfix representation:

        allowed:
            /^.*@muktopay\.com$/ OK

        rejected:
            /^.*@gmail\.com$/ REJECT External public email domain is not allowed

        restricted:
            /^ceo@muktopay\.com$/ REJECT You are not allowed to send to this recipient
            /^ceo@/i REJECT Restricted recipient
    """

    BASE_DIR = Path("/etc/postfix/ip-management")
    BACKUP_DIR = Path("/etc/postfix/backup")

    POLICIES = {
        "allowed": {
            "file": BASE_DIR / "allowed_recipient_domains",
            "title": "Allowed Recipient Domains",
            "description": (
                "Authenticated users can send email to these recipient domains."
            ),
        },
        "rejected": {
            "file": BASE_DIR / "rejected_recipient_domains",
            "title": "Rejected Recipient Domains",
            "description": (
                "Recipients belonging to these domains will be rejected."
            ),
        },
        "restricted": {
            "file": BASE_DIR / "restricted_recipient_domains",
            "title": "Restricted Recipients",
            "description": (
                "Specific recipients are restricted from receiving email. "
                "The system automatically maintains local-part restrictions."
            ),
        },
    }

    DEFAULT_REJECTED_MESSAGE = (
        "External public email domain is not allowed"
    )

    DEFAULT_RESTRICTED_MESSAGE = (
        "You are not allowed to send to this recipient"
    )

    # ------------------------------------------------------------------
    # Policy validation
    # ------------------------------------------------------------------

    def validate_policy(self, policy: str) -> None:
        if policy not in self.POLICIES:
            raise ValueError(
                f"Invalid recipient policy: {policy}"
            )

    # ------------------------------------------------------------------
    # Regex conversion
    # ------------------------------------------------------------------

    def escape_regex_value(self, value: str) -> str:
        return re.escape(value.strip())

    def plain_to_pattern(
        self,
        policy: str,
        value: str,
    ) -> str:

        self.validate_policy(policy)

        value = value.strip()

        if policy == "restricted":

            if "@" not in value:
                raise ValueError(
                    "Restricted recipient must be a complete email address."
                )

            escaped = self.escape_regex_value(value)

            return f"/^{escaped}$/"

        # allowed / rejected
        if "@" in value:
            raise ValueError(
                "Only a domain name is allowed for this policy."
            )

        escaped = self.escape_regex_value(value)

        return rf"/^.*@{escaped}$/"

    # ------------------------------------------------------------------
    # Regex -> UI plain text
    # ------------------------------------------------------------------

    def pattern_to_plain(
        self,
        policy: str,
        pattern: str,
    ) -> Optional[str]:

        self.validate_policy(policy)

        pattern = pattern.strip()

        if policy == "restricted":

            # Expected:
            # /^ceo@muktopay\.com$/
            match = re.fullmatch(
                r"/\^(.*?)\$/",
                pattern,
            )

            if not match:
                return None

            value = match.group(1)

            return self.unescape_regex_value(value)

        # allowed / rejected
        #
        # Expected:
        # /^.*@muktopay\.com$/
        match = re.fullmatch(
            r"/\^\.\*@(.+)\$/",
            pattern,
        )

        if not match:
            return None

        domain = match.group(1)

        return self.unescape_regex_value(domain)

    def unescape_regex_value(self, value: str) -> str:
        """
        Convert regex-escaped text back to normal UI text.

        Examples:

            muktopay\\.com -> muktopay.com
            ceo\\+test@muktopay\\.com -> ceo+test@muktopay.com
        """

        return re.sub(
            r"\\(.)",
            r"\1",
            value,
        )

    # ------------------------------------------------------------------
    # Restricted broad/local-part rules
    # ------------------------------------------------------------------

    def get_local_part(self, email: str) -> str:
        email = email.strip().lower()

        if "@" not in email:
            raise ValueError(
                f"Invalid recipient email address: {email}"
            )

        local_part = email.split("@", 1)[0].strip()

        if not local_part:
            raise ValueError(
                f"Invalid recipient email address: {email}"
            )

        return local_part

    def get_broad_pattern(self, email: str) -> str:
        """
        Example:

            system@muktopay.com

        becomes:

            /^system@/i
        """

        local_part = self.get_local_part(email)

        return rf"/^{re.escape(local_part)}@/i"

    def get_local_part_from_broad_pattern(
        self,
        pattern: str,
    ) -> Optional[str]:
        """
        Convert:

            /^allusers@/i

        to:

            allusers
        """

        match = re.fullmatch(
            r"/\^([^@/]+)@/i",
            pattern.strip(),
        )

        if not match:
            return None

        return self.unescape_regex_value(
            match.group(1)
        ).lower()

    def is_broad_restricted_pattern(
        self,
        pattern: str,
    ) -> bool:

        return bool(
            re.fullmatch(
                r"/\^[^@/]+@/i",
                pattern.strip(),
            )
        )

    # ------------------------------------------------------------------
    # Validation of UI values
    # ------------------------------------------------------------------

    def validate_plain_value(
        self,
        policy: str,
        value: str,
    ) -> str:

        self.validate_policy(policy)

        value = value.strip().lower()

        if not value:
            raise ValueError(
                "Value cannot be empty."
            )

        if policy == "restricted":

            # Complete email address
            if not re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+",
                value,
            ):
                raise ValueError(
                    f"Invalid recipient email address: {value}"
                )

            return value

        # --------------------------------------------------------------
        # Allowed / rejected domain
        # --------------------------------------------------------------

        if "@" in value:
            raise ValueError(
                f"Only a domain name is allowed: {value}"
            )

        domain_pattern = (
            r"^(?=.{1,253}$)"
            r"(?:[A-Za-z0-9]"
            r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"\.)+"
            r"[A-Za-z]{2,63}$"
        )

        if not re.fullmatch(
            domain_pattern,
            value,
        ):
            raise ValueError(
                f"Invalid domain name: {value}"
            )

        return value

    # ------------------------------------------------------------------
    # Parse Postfix line
    # ------------------------------------------------------------------

    def parse_line(
        self,
        policy: str,
        line: str,
    ) -> Optional[Dict]:

        self.validate_policy(policy)

        line = line.strip()

        if not line:
            return None

        if line.startswith("#"):
            return None

        # Split into:
        #
        # pattern
        # action
        # message
        #
        parts = line.split(None, 2)

        if len(parts) < 2:
            return None

        pattern = parts[0]
        action = parts[1].upper()
        message = parts[2].strip() if len(parts) >= 3 else ""

        if action not in ("OK", "REJECT"):
            return None

        value = self.pattern_to_plain(
            policy,
            pattern,
        )

        # Broad restricted rules do not have a UI value.
        if policy == "restricted" and value is None:
            if self.is_broad_restricted_pattern(pattern):
                return {
                    "value": None,
                    "pattern": pattern,
                    "action": action,
                    "message": message,
                    "hidden": True,
                    "local_part": (
                        self.get_local_part_from_broad_pattern(
                            pattern
                        )
                    ),
                }

        if value is None:
            return None

        return {
            "value": value,
            "pattern": pattern,
            "action": action,
            "message": message,
            "hidden": False,
            "local_part": (
                self.get_local_part(value)
                if policy == "restricted"
                else None
            ),
        }

    # ------------------------------------------------------------------
    # Read policy
    # ------------------------------------------------------------------

    def get_policy_entries(
        self,
        policy: str,
    ) -> List[Dict]:

        self.validate_policy(policy)

        file_path = self.POLICIES[policy]["file"]

        entries = []

        if not file_path.exists():
            return entries

        with file_path.open(
            "r",
            encoding="utf-8",
        ) as f:

            for line in f:

                parsed = self.parse_line(
                    policy,
                    line,
                )

                if not parsed:
                    continue

                # Broad restricted rules are deliberately hidden
                # from the UI.
                if (
                    policy == "restricted"
                    and parsed.get("hidden")
                ):
                    continue

                entries.append(parsed)

        return entries

    # ------------------------------------------------------------------
    # Read all policies
    # ------------------------------------------------------------------

    def get_all_policies(self) -> Dict:

        policies = {}

        for policy_name, config in self.POLICIES.items():

            policies[policy_name] = {
                "title": config["title"],
                "description": config["description"],
                "file_path": str(config["file"]),
                "entries": self.get_policy_entries(
                    policy_name
                ),
            }

        return policies

    # ------------------------------------------------------------------
    # Build Postfix line
    # ------------------------------------------------------------------

    def build_line(
        self,
        policy: str,
        value: str,
        action: str = "",
        message: str = "",
    ) -> str:

        self.validate_policy(policy)

        value = self.validate_plain_value(
            policy,
            value,
        )

        pattern = self.plain_to_pattern(
            policy,
            value,
        )

        if policy == "allowed":

            return f"{pattern} OK"

        if policy == "rejected":

            message = (
                message.strip()
                or self.DEFAULT_REJECTED_MESSAGE
            )

            return (
                f"{pattern} "
                f"REJECT "
                f"{message}"
            )

        # restricted

        message = (
            message.strip()
            or self.DEFAULT_RESTRICTED_MESSAGE
        )

        return (
            f"{pattern} "
            f"REJECT "
            f"{message}"
        )

    # ------------------------------------------------------------------
    # Backup
    # ------------------------------------------------------------------

    def backup_file(
        self,
        file_path: Path,
    ) -> Optional[Path]:

        if not file_path.exists():
            return None

        self.BACKUP_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        backup_path = (
            self.BACKUP_DIR
            / f"{file_path.name}.{timestamp}.bak"
        )

        shutil.copy2(
            file_path,
            backup_path,
        )

        return backup_path

    # ------------------------------------------------------------------
    # Normal policy application
    # ------------------------------------------------------------------

    def _apply_normal_policy(
        self,
        policy: str,
        entries: List[Dict],
    ) -> Dict:

        file_path = self.POLICIES[policy]["file"]

        new_lines = []
        seen = set()

        for entry in entries:

            value = self.validate_plain_value(
                policy,
                entry.get("value", ""),
            )

            key = value.lower()

            if key in seen:
                continue

            seen.add(key)

            message = (
                entry.get("message", "")
                or ""
            ).strip()

            line = self.build_line(
                policy,
                value,
                entry.get("action", ""),
                message,
            )

            new_lines.append(line)

        return self._write_file(
            file_path,
            new_lines,
        )

    # ------------------------------------------------------------------
    # Intelligent restricted policy
    # ------------------------------------------------------------------

    def _apply_restricted_policy(
        self,
        file_path: Path,
        entries: List[Dict],
    ) -> Dict:

        """
        Intelligent restricted recipient management.

        Example:

            UI:
                allusers@muktopay.com
                allusers@banglalink.net

        File:

            /^allusers@/i REJECT Restricted recipient
            /^allusers@muktopay\.com$/ REJECT You are not allowed...
            /^allusers@banglalink\.net$/ REJECT You are not allowed...

        If one exact recipient is removed, the broad rule remains
        while another recipient with the same local-part exists.

        When the last recipient for a local-part is removed, the
        corresponding broad rule is also removed.
        """

        existing_lines = []

        if file_path.exists():

            with file_path.open(
                "r",
                encoding="utf-8",
            ) as f:

                existing_lines = [
                    line.rstrip("\n")
                    for line in f
                ]

        # --------------------------------------------------------------
        # Existing broad rules
        # --------------------------------------------------------------

        existing_broad_rules = {}

        # Existing exact rules
        existing_exact_rules = {}

        # Comments / unmanaged lines
        other_lines = []

        for line in existing_lines:

            stripped = line.strip()

            if not stripped:
                continue

            if stripped.startswith("#"):
                other_lines.append(line)
                continue

            parts = stripped.split(
                None,
                2,
            )

            if not parts:
                continue

            pattern = parts[0]

            # ----------------------------------------------------------
            # Broad rule
            # ----------------------------------------------------------

            local_part = (
                self.get_local_part_from_broad_pattern(
                    pattern
                )
            )

            if local_part:

                existing_broad_rules[
                    local_part
                ] = line

                continue

            # ----------------------------------------------------------
            # Exact recipient
            # ----------------------------------------------------------

            parsed = self.parse_line(
                "restricted",
                stripped,
            )

            if parsed and parsed.get("value"):

                value = parsed["value"].lower()

                existing_exact_rules[
                    value
                ] = line

                continue

            # ----------------------------------------------------------
            # Anything else
            # ----------------------------------------------------------

            other_lines.append(line)

        # --------------------------------------------------------------
        # Requested UI state
        # --------------------------------------------------------------

        requested_exact_rules = {}

        requested_local_parts = set()

        for entry in entries:

            value = self.validate_plain_value(
                "restricted",
                entry.get("value", ""),
            )

            value = value.lower()

            if value in requested_exact_rules:
                continue

            message = (
                entry.get("message", "")
                or ""
            ).strip()

            if not message:
                message = (
                    self.DEFAULT_RESTRICTED_MESSAGE
                )

            line = self.build_line(
                "restricted",
                value,
                "REJECT",
                message,
            )

            requested_exact_rules[
                value
            ] = line

            local_part = self.get_local_part(
                value
            )

            requested_local_parts.add(
                local_part
            )

        # --------------------------------------------------------------
        # Intelligent broad rules
        # --------------------------------------------------------------

        final_broad_rules = {}

        for local_part in sorted(
            requested_local_parts
        ):

            # Existing broad rule:
            # preserve it.
            if local_part in existing_broad_rules:

                final_broad_rules[
                    local_part
                ] = existing_broad_rules[
                    local_part
                ]

            else:

                # No broad rule:
                # create it automatically.
                broad_pattern = (
                    rf"/^{re.escape(local_part)}@/i"
                )

                final_broad_rules[
                    local_part
                ] = (
                    f"{broad_pattern} "
                    f"REJECT Restricted recipient"
                )

        # --------------------------------------------------------------
        # Final file
        # --------------------------------------------------------------

        final_lines = []

        # Preserve comments / unmanaged content.
        final_lines.extend(
            other_lines
        )

        # Broad rules first.
        final_lines.extend(
            final_broad_rules[
                local_part
            ]
            for local_part in sorted(
                final_broad_rules
            )
        )

        # Exact recipient rules.
        final_lines.extend(
            requested_exact_rules[
                value
            ]
            for value in sorted(
                requested_exact_rules
            )
        )

        return self._write_file(
            file_path,
            final_lines,
        )

    # ------------------------------------------------------------------
    # Atomic file write
    # ------------------------------------------------------------------

    def _write_file(
        self,
        file_path: Path,
        lines: List[str],
    ) -> Dict:

        self.BASE_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        backup_path = self.backup_file(
            file_path
        )

        content = ""

        if lines:
            content = (
                "\n".join(lines)
                + "\n"
            )

        temp_file = Path(
            f"{file_path}.tmp"
        )

        stat_info = None

        if file_path.exists():
            stat_info = file_path.stat()

        try:

            with temp_file.open(
                "w",
                encoding="utf-8",
            ) as f:

                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            # Preserve ownership and permissions.
            if stat_info:

                os.chmod(
                    temp_file,
                    stat_info.st_mode,
                )

                try:
                    os.chown(
                        temp_file,
                        stat_info.st_uid,
                        stat_info.st_gid,
                    )
                except PermissionError:
                    # If the application does not have permission
                    # to chown, leave ownership unchanged.
                    pass

            os.replace(
                temp_file,
                file_path,
            )

            return {
                "success": True,
                "file": str(file_path),
                "backup": (
                    str(backup_path)
                    if backup_path
                    else None
                ),
                "entries": len(lines),
            }

        except Exception:

            if temp_file.exists():
                temp_file.unlink()

            raise