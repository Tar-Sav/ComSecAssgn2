
import json
from datetime import datetime, timezone
from pathlib import Path


LOG_FILE = Path("release_log.jsonl")


def log_attempt(operation, release_folder, publisher_id,
                result, reason):
    """Append a signing or verification attempt to the audit log."""

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "release_folder": str(release_folder),
        "publisher_id": publisher_id,
        "result": result,
        "reason": reason
    }

    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(json.dumps(record) + "\n")
