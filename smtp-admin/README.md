# SMTP Admin Dashboard

Lightweight administration dashboard for Oracle Linux 9.7 + Postfix + Redis.

Stack:
- Python 3.9+
- FastAPI
- Jinja2
- HTMX
- Bootstrap 5
- redis-py
- ldap3 for Active Directory authentication
- systemd + Nginx

## Important

This application is intentionally a controlled management layer. It does not expose a shell or arbitrary Redis commands.

Before production:
1. Review every sudo rule.
2. Put the application behind HTTPS.
3. Use a dedicated Linux service account.
4. Configure AD settings in `/etc/smtp-admin/smtp-admin.env`.
5. Configure role mappings.
6. Test Postfix changes on a non-production relay first.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

For local development, `AUTH_MODE=dev` creates a development login. Do not use this in production.

## Production

See `docs/INSTALL_OEL9.md`.

The application never uses `shell=True`. Privileged Postfix operations are delegated to `/usr/local/sbin/smtp-admin-postfix-helper`, which only accepts fixed subcommands.


## Existing Postfix configuration/map model

The dashboard is designed to operate on the **existing Postfix configuration and map files**.

It does not create a second policy hierarchy such as `/etc/postfix/policy`.

The dashboard discovers currently referenced map specifications through `postconf`, for example:

```text
hash:/etc/postfix/access
hash:/etc/postfix/sender_access
hash:/etc/postfix/recipient_access
pcre:/etc/postfix/header_checks
```

Only explicitly allow-listed map filenames are editable. Before a map is changed:

```text
existing map
  -> timestamped backup
  -> atomic source-file update
  -> postmap
  -> postfix check
  -> postfix reload
  -> audit log
```

If validation or reload fails, the previous source map is restored.

The dashboard also provides `postconf -n` as a read-only effective configuration view.

**Important:** existing `main.cf` restriction chains are not automatically rewritten. The dashboard manages maps already referenced by those chains, preserving the current Postfix architecture.
