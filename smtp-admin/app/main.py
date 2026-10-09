from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from itsdangerous import URLSafeTimedSerializer
from .config import settings
from .auth.routes import router as auth_router
from .dashboard.routes import router as dashboard_router
from .policies.routes import router as policies_router
from .redis_admin.routes import router as redis_router
from .postfix.routes import router as postfix_router
from .audit.routes import router as audit_router
from .certificates.routes import router as certificates_router
from .relay.routes import router as relay_router
from .ip_management.routes import router as ip_management_router
from .recipient_domains.routes import router as recipient_domains_router
from .smtp_policy.routes import router as smtp_policy_router
from .redis_admin.config_routes import router as redis_config_router
from .redis_admin.redis_data_route import router as redis_data_router
from .redis_admin.redis_status_route import router as redis_status_router
from .mail_queue.routes import router as mail_queue_router
from .about.routes import router as about_router
from .ldap_admin.routes import router as ldap_router
from .monitoring.routes import router as monitoring_router
from .profile.routes import router as profile_router
from .account_security.routes import router as account_security_router
from .server_inventory.routes import router as server_inventory_router
from .installation.routes import router as installation_router
from .postfix.control_routes import router as postfix_control_router
from .backups.routes import router as backups_router
from app.monitoring.information_routes import router as information_router









app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, max_age=settings.session_timeout_minutes * 60, https_only=True, same_site="lax")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")
app.state.templates = templates
serializer = URLSafeTimedSerializer(settings.session_secret, salt="smtp-admin-session")

app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(policies_router)
app.include_router(redis_router)
app.include_router(postfix_router)
app.include_router(audit_router)
app.include_router(certificates_router)
app.include_router(relay_router)
app.include_router(ip_management_router)
app.include_router(recipient_domains_router)
app.include_router(smtp_policy_router)
app.include_router(redis_config_router)
app.include_router(redis_data_router)
app.include_router(redis_status_router)
app.include_router(mail_queue_router)
app.include_router(about_router)
app.include_router(ldap_router)
app.include_router(monitoring_router)
app.include_router(profile_router)
app.include_router(account_security_router)
app.include_router(server_inventory_router)
app.include_router(installation_router)
app.include_router(postfix_control_router)
app.include_router(backups_router)
app.include_router(information_router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

@app.get("/")
async def root(request: Request):
    if request.session.get("username"):
        return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)
