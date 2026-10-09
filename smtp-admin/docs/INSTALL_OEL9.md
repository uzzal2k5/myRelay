# OEL 9.7 Production Installation

## 1. Copy application

Install under:

`/opt/smtp-admin`

Create service account:

```bash
useradd --system --home /opt/smtp-admin --shell /sbin/nologin smtpadmin
```

## 2. Python environment

```bash
cd /opt/smtp-admin
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Configuration

Create:

`/etc/smtp-admin/smtp-admin.env`

Copy values from `.env.example`.

Generate a strong session secret:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Set permissions:

```bash
chown root:smtpadmin /etc/smtp-admin/smtp-admin.env
chmod 0640 /etc/smtp-admin/smtp-admin.env
```

## 4. Privileged helper

Install:

```bash
install -o root -g root -m 0750 scripts/smtp-admin-postfix-helper-backup \
  /usr/local/sbin/smtp-admin-postfix-helper-backup

install -o root -g root -m 0440 sudoers/smtp-admin-postfix \
  /etc/sudoers.d/smtp-admin-postfix
visudo -cf /etc/sudoers.d/smtp-admin-postfix
```

If your Postfix binary is not `/usr/sbin/postfix`, change the helper after verifying with:

```bash
command -v postfix
command -v postmap
```

## 5. systemd

```bash
cp systemd/smtp-admin.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now smtp-admin
systemctl status smtp-admin
```

## 6. Nginx

Edit:

`nginx/smtp-admin.conf`

Set your actual DNS name and certificate paths.

Then:

```bash
cp nginx/smtp-admin.conf /etc/nginx/conf.d/smtp-admin.conf
nginx -t
systemctl enable --now nginx
systemctl reload nginx
```

## 7. AD

The application uses LDAP/LDAPS to:
1. Find the user.
2. Check membership in `MP-SMTP-Users`.
3. Validate the supplied AD password.
4. Map AD groups to application roles.

Use LDAPS where possible.

For production, use a dedicated read-only AD service account for directory lookup.

## 8. Postfix policy model

Application-managed maps are placed under:

`/etc/postfix/policy/`

The application performs:

```text
write map
→ postmap
→ postfix check
→ postfix reload
→ audit
```

A failed validation does not reload Postfix.

## 9. Redis

The application only manages keys under:

`smtp:policy:*`

It does not expose arbitrary Redis commands.

## 10. Firewall

Expose only HTTPS from approved administrator networks.

Do not expose port 8080.

Example verification:

```bash
ss -lntp | grep -E ':443|:8080'
```

Expected:
- Nginx: 443
- Uvicorn: 127.0.0.1:8080

## 11. Logs

Application/service:

```bash
journalctl -u smtp-admin -f
```

Audit:

`/var/log/smtp-admin/audit.log`

Configure logrotate before production.

## 12. Important Postfix integration note

The application does not automatically rewrite your existing `main.cf`.

Before enabling a policy map, explicitly integrate the generated map into your existing Postfix restriction chain. Preserve the current production configuration and test with:

```bash
postfix check
postconf -n
postmap -q example.com /etc/postfix/policy/allowed_domains
```
