from pydantic import BaseModel
import os
import json
from app.services.rollback.history import list_snapshots, get_snapshot_content, convert_to_rollback


class SnapshotRequest(BaseModel):
    ip: str
    username: str



def get_latest_snapshot_for_device(ip, username):
    snapshots = list_snapshots()["snapshots"]
    filtered = [s for s in snapshots if s["ip"] == ip and s["username"] == username]
    if not filtered:
        return None
    latest = sorted(filtered, key=lambda x: x["timestamp"], reverse=True)[0]
    return get_snapshot_content(latest["id"])["snapshot"]

def preview_rollback(request: SnapshotRequest):
    snapshot = get_latest_snapshot_for_device(request.ip, request.username)
    if not snapshot:
        return {"status": "not_found", "output": "No matching rollback snapshot found."}
    
    return {
        "status": "ok",
        "output": convert_to_rollback(snapshot["config"])
    }
