
### Before restarting

Run syntax validation:

```bash
cd /home/shafiqul.islam/smtp-portal/smtp-admin

python -m py_compile app/auth/ad.py
```

Then test STARTTLS directly from the server:

```bash
openssl s_client \
  -connect gzvwmpudm01.muktopay.com:389 \
  -starttls ldap </dev/null
```

You should see a successful TLS handshake.

Then start the application:

```bash
uvicorn app.main:app \
  --host 172.17.65.37 \
  --port 8080 \
  --log-level debug
```

During login, the expected sequence in your application log is:

```text
LDAP TCP connection established
LDAP STARTTLS established successfully
LDAP service account bind successful
AD user found
AD group authorization successful
User LDAP STARTTLS established
AD user password authentication successful
AD authentication successful
```

**One important point:** this implementation requires the AD certificate/CA to be trusted by the OEL server because STARTTLS is still TLS encryption. It does **not** mean port 389 is unencrypted.
