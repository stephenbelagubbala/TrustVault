
import json
import os
from datetime import datetime, timezone

AUDIT_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "audit.log"
)


def log_audit(action, username, document, details=""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "username": str(username),
        "document": document,
        "details": details
    }

    with open(AUDIT_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")
