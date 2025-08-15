from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from app.services.ai_engine.gpt_engine import gpt_conversational_with_config
from app.services.ssh_engine.ssh_connector import send_config_to_device
from app.core.database import get_db
from app.models.base import Agent
from datetime import datetime
import json

router = APIRouter()
connected_clients = set()

# Temporary in-memory storage per client
client_context = {}

def log_agent_token_event(db, agent_id, event, user_id=None, ip_address=None, details=None):
    """Log agent token events"""
    try:
        from app.models.base import AgentTokenAuditLog
        audit = AgentTokenAuditLog(
            agent_id=agent_id,
            event_type=event,
            timestamp=datetime.utcnow(),
            user_id=user_id,
            ip_address=ip_address,
            details=details or {}
        )
        db.add(audit)
        db.commit()
    except Exception as e:
        print(f"Error logging agent event: {e}")

@router.websocket("/ws/agent/{agent_token}")
async def agent_websocket(websocket: WebSocket, agent_token: str):
    """WebSocket endpoint for agent connections."""
    try:
        # Get database session directly
        from app.core.database import SessionLocal
        db = SessionLocal()
        
        try:
            # Validate agent token
            agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
            if not agent:
                await websocket.close(code=4001, reason="Invalid agent token")
                return
            
            if agent.token_status != "active":
                await websocket.close(code=4003, reason="Agent token is not active")
                return
            
            await websocket.accept()
            
            # Update agent status to online
            agent.status = "online"
            agent.last_heartbeat = datetime.utcnow()
            agent.last_used_at = datetime.utcnow()
            db.commit()
            
            # Log the connection
            log_agent_token_event(db, agent.id, "websocket_connected")
            
            try:
                while True:
                    data = await websocket.receive_text()
                    try:
                        payload = json.loads(data)
                        message_type = payload.get("type", "")
                        
                        if message_type == "heartbeat":
                            # Update heartbeat
                            agent.last_heartbeat = datetime.utcnow()
                            agent.last_used_at = datetime.utcnow()
                            db.commit()
                            
                            # Send pong response
                            await websocket.send_text(json.dumps({
                                "type": "pong",
                                "timestamp": datetime.utcnow().isoformat()
                            }))
                        
                        elif message_type == "discovery_result":
                            # Handle discovery results
                            devices = payload.get("devices", [])
                            subnet = payload.get("subnet", "")
                            
                            # Process discovered devices
                            for device_data in devices:
                                # You can add device processing logic here
                                pass
                            
                            await websocket.send_text(json.dumps({
                                "type": "discovery_ack",
                                "message": f"Received {len(devices)} devices from {subnet}"
                            }))
                        
                        else:
                            # Echo back unknown message types
                            await websocket.send_text(json.dumps({
                                "type": "echo",
                                "data": payload
                            }))
                            
                    except json.JSONDecodeError:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Invalid JSON format"
                        }))
                        
            except WebSocketDisconnect:
                # Update agent status to offline
                agent.status = "offline"
                db.commit()
                log_agent_token_event(db, agent.id, "websocket_disconnected")
                
        finally:
            db.close()
            
    except Exception as e:
        if websocket.client_state.value < 3:  # Not closed yet
            await websocket.close(code=4000, reason=f"Internal error: {str(e)}")
        log_agent_token_event(None, None, "websocket_error", details={"error": str(e)})


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    print("Client connected")

    # Init context for this client
    client_context[websocket] = {
        "config": "",
        "device": {
            "ip": "192.168.1.1",             # 🔧 You can dynamically fetch this from UI later
            "username": "admin",
            "password": "yourpassword"
        }
    }

    try:
        while True:
            data = await websocket.receive_text()
            print(f"Received from client: {data}")

            try:
                payload = json.loads(data)
                message = payload.get("message", "")
                action = payload.get("action", "")

                if action == "approve":
                    context = client_context[websocket]
                    config = context["config"]
                    device = context["device"]

                    print(f"🛠️ Applying config to {device['ip']}:\n{config}")

                    result = send_config_to_device(
                        ip=device["ip"],
                        username=device["username"],
                        password=device["password"],
                        config_commands=config
                    )

                    await websocket.send_text(json.dumps({
                        "status": "applied",
                        "result": result
                    }))
                    continue

                if message:
                    result = gpt_conversational_with_config(message)
                    if "error" in result:
                        await websocket.send_text(json.dumps({ "error": result["error"] }))
                    else:
                        client_context[websocket]["config"] = result["cli_config"]  # Save for later
                        await websocket.send_text(json.dumps({
                            "voice": "Here's the configuration. Let me know if you approve it.",
                            "config": result["cli_config"]
                        }))

            except Exception as e:
                await websocket.send_text(json.dumps({
                    "error": f"Internal error: {str(e)}"
                }))

    except WebSocketDisconnect:
        connected_clients.remove(websocket)
        client_context.pop(websocket, None)
        print("Client disconnected")
