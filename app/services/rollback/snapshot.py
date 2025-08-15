from fastapi import Request
from pydantic import BaseModel
from app.services.ssh_engine.ssh_connector import send_config_to_device, run_show_command
import json
import os
from datetime import datetime
from app.services.rollback.history import get_latest_snapshot_for_device
from typing import Union

SNAPSHOT_FILE = "rollback_snapshot.json"

class SnapshotRequest(BaseModel):
    ip: str
    username: str
    config: str

class RollbackRequest(BaseModel):
    ip: str
    username: str
    password: str

def log_snapshot(snapshot: SnapshotRequest):
    try:
        snapshots = []
        if os.path.exists(SNAPSHOT_FILE):
            with open(SNAPSHOT_FILE, "r") as f:
                snapshots = json.load(f)

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip": snapshot.ip,
            "username": snapshot.username,
            "config": snapshot.config
        }
        snapshots.append(entry)

        with open(SNAPSHOT_FILE, "w") as f:
            json.dump(snapshots, f, indent=2)
        return {"status": "saved", "message": "Snapshot saved for rollback"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def generate_inverse_config(config: str) -> str:
    rollback_cmds = []
    for line in config.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue

        if stripped.startswith("vlan"):
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].isdigit():
                rollback_cmds.append(f"no vlan {parts[1]}")
        elif stripped.startswith("interface"):
            parts = stripped.split()
            if len(parts) >= 2:
                rollback_cmds.append(f"default interface {parts[1]}")
        else:
            rollback_cmds.append(f"no {stripped}")

    # rollback_cmds.append("write memory")
    return "\n".join(rollback_cmds)

def rollback_latest(request: Union[RollbackRequest, dict]):
    print("🔥 rollback_latest() triggered")
    try:
        if isinstance(request, dict):
            ip = request.get("ip")
            username = request.get("username")
            password = request.get("password")
        else:
            ip = request.ip
            username = request.username
            password = request.password

        print(f"👉 Using device: {ip}, {username}")

        snapshot = get_latest_snapshot_for_device(ip, username)
        if not snapshot:
            print("❌ No snapshot found!")
            return {"status": "error", "output": "No snapshot found for rollback."}

        print("📸 Snapshot found")

        rollback_config = generate_inverse_config(snapshot["config"])

        print("🧠 Rollback config generated:")
        print(rollback_config)

        print("🚀 Sending rollback config to device...")

        success, message = send_config_to_device(
            ip=ip,
            username=username,
            password=password,
            config=rollback_config
        )
        print(f"✅ Rollback sent — Success: {success}, Message: {message}")
        return {
            "status": "ok" if success else "error",
            "output": message
        }

    except Exception as e:
        print(f"🔥 Exception occurred: {e}")
        return {"status": "error", "output": str(e)}