
import logging
import os
import re
import shutil
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

CERT_DIR = Path("/etc/postfix/tls")
BACKUP_DIR = Path("/etc/postfix/backup/certificates")
AUDIT_LOG = Path("/var/log/smtp-admin/audit.log")

# Only certificate files directly inside CERT_DIR are allowed.
CERT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+\.crt$")


class CertificateError(Exception):
    """Raised for certificate read, validation, or save errors."""


class CertificateService:
    def __init__(self, backup_path):
        self.backup_path = backup_path

    def _get_path(self, filename: str) -> Path:
        if not CERT_NAME_PATTERN.fullmatch(filename):
            raise CertificateError("Invalid certificate filename.")

        path = CERT_DIR / filename

        # Do not follow a symlink outside the certificate directory.
        if path.is_symlink():
            raise CertificateError("Symbolic-link certificate files are not allowed.")

        resolved_parent = path.parent.resolve()
        if resolved_parent != CERT_DIR.resolve():
            raise CertificateError("Invalid certificate path.")

        return path

    def list_certificates(self) -> list[str]:
        if not CERT_DIR.is_dir():
            raise CertificateError(f"Certificate directory not found: {CERT_DIR}")

        return sorted(
            path.name
            for path in CERT_DIR.iterdir()
            if path.is_file()
            and not path.is_symlink()
            and CERT_NAME_PATTERN.fullmatch(path.name)
        )

    def read_certificate(self, filename: str) -> str:
        path = self._get_path(filename)

        if not path.is_file():
            raise CertificateError(f"Certificate file not found: {filename}")

        try:
            return path.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            logger.exception("Failed to read certificate file %s", filename)
            raise CertificateError("Unable to read certificate file.") from exc

    def get_certificate_details(self, filename: str) -> dict:
        path = self._get_path(filename)

        if not path.is_file():
            raise CertificateError(f"Certificate file not found: {filename}")

        try:
            decoded = ssl._ssl._test_decode_cert(str(path))
        except Exception as exc:
            logger.exception("Failed to parse certificate %s", filename)
            raise CertificateError(
                "Certificate could not be parsed. Check that it is a valid PEM certificate."
            ) from exc

        def format_name(name):
            if not name:
                return "Not available"
            return ", ".join(
                f"{key}={value}"
                for rdn in name
                for key, value in rdn
            )

        def format_time(value):
            if not value:
                return "Not available"
            try:
                return datetime.strptime(
                    value, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                return value

        not_before = decoded.get("notBefore")
        not_after = decoded.get("notAfter")

        def parse_cert_time(value):
            if not value:
                return None
            try:
                return datetime.strptime(
                    value, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                return None

        now = datetime.now(timezone.utc)
        valid_from = parse_cert_time(not_before)
        valid_until = parse_cert_time(not_after)

        if valid_from and now < valid_from:
            status = "Not yet valid"
        elif valid_until and now > valid_until:
            status = "Expired"
        elif valid_from and valid_until:
            status = "Valid"
        else:
            status = "Validity dates unavailable"

        subject_alt_names = decoded.get("subjectAltName", [])

        return {
            "filename": filename,
            "subject": format_name(decoded.get("subject")),
            "issuer": format_name(decoded.get("issuer")),
            "serial_number": decoded.get("serialNumber", "Not available"),
            "version": decoded.get("version", "Not available"),
            "valid_from": format_time(not_before),
            "valid_until": format_time(not_after),
            "status": status,
            "subject_alt_names": [
                f"{kind}: {value}" for kind, value in subject_alt_names
            ],
        }

    def _validate_pem(self, content: str) -> None:
        if not content.strip():
            raise CertificateError("Certificate content cannot be empty.")

        if "-----BEGIN CERTIFICATE-----" not in content:
            raise CertificateError("PEM certificate header is missing.")

        if "-----END CERTIFICATE-----" not in content:
            raise CertificateError("PEM certificate footer is missing.")

        # Validate the PEM certificate using OpenSSL via Python's ssl module.
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="ascii",
                suffix=".crt",
                delete=False,
            ) as temp_file:
                temp_file.write(content)
                temp_path = Path(temp_file.name)

            ssl._ssl._test_decode_cert(str(temp_path))
        except (UnicodeError, ValueError, ssl.SSLError, OSError) as exc:
            raise CertificateError(
                "Invalid PEM certificate. Please verify the certificate content."
            ) from exc
        finally:
            if temp_path:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    logger.warning("Could not remove temporary certificate file")

    def save_certificate(
        self,
        filename: str,
        content: str,
        actor: str,
    ) -> dict:
        path = self._get_path(filename)

        if not path.is_file():
            raise CertificateError(f"Certificate file not found: {filename}")

        self._validate_pem(content)

        # Require the new certificate to be currently valid.
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="ascii",
                suffix=".crt",
                delete=False,
            ) as temp_file:
                temp_file.write(content)
                temp_path = Path(temp_file.name)

            decoded = ssl._ssl._test_decode_cert(str(temp_path))
            now = datetime.now(timezone.utc)

            not_before = datetime.strptime(
                decoded["notBefore"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(
                decoded["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            if now < not_before:
                raise CertificateError("The certificate is not yet valid.")
            if now > not_after:
                raise CertificateError("The certificate has expired.")
        finally:
            if temp_path:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    logger.warning("Could not remove temporary certificate file")

        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        old_stat = path.stat()
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = BACKUP_DIR / f"{filename}.{timestamp}.bak"

        try:
            shutil.copy2(path, backup_path)

            # Write to a temporary file in the same directory, then atomically replace.
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="ascii",
                dir=str(path.parent),
                prefix=f".{filename}.",
                suffix=".tmp",
                delete=False,
            ) as temp_file:
                temp_file.write(content)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                new_path = Path(temp_file.name)

            os.chmod(new_path, old_stat.st_mode & 0o777)

            # Preserve the existing owner/group where permitted.
            try:
                os.chown(new_path, old_stat.st_uid, old_stat.st_gid)
            except PermissionError:
                logger.warning(
                    "Could not preserve certificate ownership for %s", filename
                )

            os.replace(new_path, path)

            self._write_audit(
                actor=actor,
                action="certificate_updated",
                filename=filename,
                backup=str(backup_path),
            )

            logger.info("Certificate %s updated by %s", filename, actor)

            return {
                "filename": filename,
                "backup": str(backup_path),
                "message": "Certificate saved successfully.",
            }

        except Exception:
            logger.exception("Failed to save certificate %s", filename)
            raise

    def _write_audit(
        self,
        actor: str,
        action: str,
        filename: str,
        backup: str = "",
    ) -> None:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

        entry = (
            f"{datetime.now(timezone.utc).isoformat()} "
            f"actor={actor!r} action={action!r} "
            f"file={filename!r} backup={backup!r}\n"
        )

        with AUDIT_LOG.open("a", encoding="utf-8") as audit_file:
            audit_file.write(entry)