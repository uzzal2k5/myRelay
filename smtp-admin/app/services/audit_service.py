from pathlib import Path
from datetime import datetime, timezone
import json
from ..config import settings

def audit(request, action, object_name, old_value=None, new_value=None, result="SUCCESS", error=None):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": request.session.get("username"),
        "role": request.session.get("role"),
        "source_ip": request.client.host if request.client else None,
        "action": action,
        "object": object_name,
        "old_value": old_value,
        "new_value": new_value,
        "result": result,
        "error": error,
    }
    path = Path(settings.audit_log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
