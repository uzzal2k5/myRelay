from datetime import datetime, timezone

# ... inside login_post(), right where the session is populated:

request.session["username"] = user["username"]
request.session["role"] = user["role"]
request.session["groups"] = user.get("groups", [])
request.session["login_time"] = datetime.now(timezone.utc).isoformat()  # add this line