
import os
import json
from datetime import datetime
from uuid import uuid4
from app.services.ssh_engine.ssh_connector import send_config_to_device
from pydantic import BaseModel




SNAPSHOT_DIR = "snapshots"
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

def log_snapshot(request):
    snapshot_id = str(uuid4())
    filename = os.path.join(SNAPSHOT_DIR, f"{snapshot_id}.json")
    snapshot = {
        "ip": request.ip,
        "username": request.username,
        "config": request.config,
        "timestamp": datetime.utcnow().isoformat()
    }
    with open(filename, "w") as f:
        json.dump(snapshot, f)
    return {"status": "saved", "id": snapshot_id}

def list_snapshots():
    snapshots = []
    for fname in os.listdir(SNAPSHOT_DIR):
        if fname.endswith(".json"):
            with open(os.path.join(SNAPSHOT_DIR, fname)) as f:
                snap = json.load(f)
                snapshots.append({
                    "id": fname.replace(".json", ""),
                    "timestamp": snap.get("timestamp", ""),
                    "ip": snap.get("ip", ""),
                    "username": snap.get("username", "")
                })
    return {"snapshots": sorted(snapshots, key=lambda x: x["timestamp"])}

def get_snapshot_content(snapshot_id):
    filename = os.path.join(SNAPSHOT_DIR, f"{snapshot_id}.json")
    if not os.path.exists(filename):
        return {"error": "Snapshot not found"}
    with open(filename) as f:
        return {"snapshot": json.load(f)}

class SnapshotRequest(BaseModel):  # ✅ Make it a Pydantic model
    ip: str
    username: str
    password: str

def get_latest_snapshot_for_device(ip, username):
    snapshots = list_snapshots()["snapshots"]
    filtered = [s for s in snapshots if s["ip"] == ip and s["username"] == username]
    if not filtered:
        return None
    latest = sorted(filtered, key=lambda x: x["timestamp"], reverse=True)[0]
    return get_snapshot_content(latest["id"])["snapshot"]

def convert_to_rollback(config):
    lines = config.strip().split("\n")
    rollback_lines = []
    for line in lines:
        if line.startswith("interface "):
            rollback_lines.append("no " + line)
        elif line.startswith("vlan "):
            rollback_lines.append("no " + line)
        elif line.startswith("name "):
            continue
        else:
            rollback_lines.append("no " + line)
    return "\n".join(rollback_lines)


def rollback_to_snapshot(request: SnapshotRequest):
    snapshot = get_latest_snapshot_for_device(request.ip, request.username)
    if not snapshot:
        return False, "No snapshot found for this device."

    config = convert_to_rollback(snapshot["config"])

    success, message = send_config_to_device(
        ip=request.ip,
        username=request.username,
        password=request.password,
        config=config
    )
    return success, message