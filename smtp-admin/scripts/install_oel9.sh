#!/bin/bash
set -euo pipefail

APP=/opt/smtp-admin

if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

dnf install -y python3 python3-pip nginx policycoreutils-python-utils

id smtpadmin >/dev/null 2>&1 || useradd --system --home "$APP" --shell /sbin/nologin smtpadmin

mkdir -p "$APP" /etc/smtp-admin /var/log/smtp-admin /etc/postfix/backup
chown -R smtpadmin:smtpadmin "$APP" /var/log/smtp-admin
chmod 0750 /etc/smtp-admin
chmod 0750 /etc/postfix/backup

python3 -m venv "$APP/.venv"
"$APP/.venv/bin/pip" install --upgrade pip
"$APP/.venv/bin/pip" install -r "$APP/requirements.txt"

install -o root -g root -m 0750 scripts/smtp-admin-postfix-helper /usr/local/sbin/smtp-admin-postfix-helper
install -o root -g root -m 0440 sudoers/smtp-admin-postfix /etc/sudoers.d/smtp-admin-postfix

echo "Install completed."
echo "Create /etc/smtp-admin/smtp-admin.env and copy systemd/smtp-admin.service to /etc/systemd/system/."
