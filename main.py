from fastapi import UploadFile, File, Body, Request, WebSocket, WebSocketDisconnect, FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

# Rate limiting imports
from app.core.working_rate_limiting import rate_limit_dependency, get_rate_limit_stats_working

# Internal imports with new structure
from app.services.ai_engine.gpt_engine import gpt_generate_config, gpt_generate_show_command
from app.services.ssh_engine.ssh_connector import send_config_to_device, run_show_command, get_hostname
from app.config.logger import log_config
from app.utils.sanitizer import clean_cli_output
from app.services.rollback.preview import preview_rollback
from app.services.rollback.snapshot import rollback_latest, log_snapshot
from app.services.ai_engine.dialogflow_webhook import dialogflow_webhook
from app.api.websocket import router as websocket_router
from app.services.rollback.history import log_snapshot, rollback_to_snapshot, SnapshotRequest
from app.core.database import engine, Base
from app.models.base import User, Company, Feature, CompanyFeature, Organization, Network, DeviceSNMP, Device, UserOrganizationAccess, UserNetworkAccess, UserFeatureAccess, LogType, DeviceLog
from app.models.topology import DeviceTopology, InterfaceTopology, NeighborTopology
from app.api.v1.endpoints import users, devices, org_network, companies
from app.api.v1.api import api_router
from app.core.secure_config import secure_settings as settings
from app.core.security_middleware import create_security_middleware
from app.core.secure_upload import SecureFileUpload
from app.schemas.secure_requests import (
    SecureCommandRequest,
    SecureApplyConfigRequest,
    SecureSnapshotRequest,
    SecurePreviewRequest,
    SecureRollbackRequest,
    SecureShowCommandRequest,
    SecureAskAIShowRequest
)

# External imports
try:
    import whisper
    WHISPER_AVAILABLE = True
except ImportError:
    WHISPER_AVAILABLE = False

try:
    from pydub import AudioSegment
    AUDIO_PROCESSING_AVAILABLE = True
except ImportError:
    AUDIO_PROCESSING_AVAILABLE = False

import tempfile
import logging
import os
from datetime import datetime

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Health endpoint for deployment checks
@app.get("/health")
async def health_check():
    return {"status": "ok"}

# Add security middleware
app.add_middleware(create_security_middleware())

# Add CORS middleware with secure configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
    expose_headers=["*"],
    max_age=86400  # Cache preflight requests for 24 hours (Chrome-friendly)
)

# Rate limiting is applied via decorators on individual endpoints

# Add Chrome-compatible CORS headers
@app.middleware("http")
async def add_chrome_cors_headers(request, call_next):
    response = await call_next(request)
    
    # Get the origin from request headers
    origin = request.headers.get("origin")
    
    # Handle CORS for all requests (Chrome compatibility)
    if origin and origin in settings.BACKEND_CORS_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        
        # Handle preflight requests
        if request.method == "OPTIONS":
            response.headers["Access-Control-Allow-Methods"] = ", ".join(settings.CORS_ALLOW_METHODS)
            response.headers["Access-Control-Allow-Headers"] = ", ".join(settings.CORS_ALLOW_HEADERS)
            response.headers["Access-Control-Max-Age"] = "86400"
    
    # WebSocket-specific CORS handling
    if request.url.path.startswith("/ws"):
        if origin in settings.BACKEND_CORS_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return response

# Create all database tables (disabled for production deployment)
# Base.metadata.create_all(bind=engine)

# Include the API router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Include other routers that are not part of the API router
app.include_router(users.router)
app.include_router(org_network.router)
app.include_router(companies.router)

# Add explicit OPTIONS handler for CORS preflight
@app.options("/users/login")
async def options_login():
    return {"message": "OK"}


# Enable Authorize button in Swagger UI
from fastapi.openapi.utils import get_openapi

# Create logs directory if it doesn't exist (commented out for production)
# os.makedirs("data/logs", exist_ok=True)

# Configure logging (simplified for production)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Only console logging for production
    ]
)

logger = logging.getLogger(__name__)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Cisco AI Config API",
        version="1.0.0",
        description="API with JWT authentication for Network devices",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    for path in openapi_schema["paths"].values():
        for method in path.values():
            method.setdefault("security", []).append({"BearerAuth": []})

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


# Legacy request models (keeping for backward compatibility)
class CommandRequest(BaseModel):
    text: str

class ApplyConfigRequest(BaseModel):
    ip: str
    username: str
    password: str
    config: str

class SnapshotRequest(BaseModel):
    ip: str
    username: str
    config: str

class PreviewRequest(BaseModel):
    ip: str
    username: str

class RollbackRequest(BaseModel):
    ip: str
    username: str
    password: str

class ShowCommandRequest(BaseModel):
    ip: str
    username: str
    password: str
    command: str

class AskAIShowRequest(BaseModel):
    ip: str
    username: str
    password: str
    question: str

@app.post("/ai/command")
async def ai_command_handler(
    request: SecureCommandRequest,
    rate_limit: bool = Depends(rate_limit_dependency("api", "ai_commands"))
):
    raw_config = gpt_generate_config(request.text)
    cleaned_config = clean_cli_output(raw_config)
    return {
        "user_request": request.text,
        "generated_config": cleaned_config,
        "status": "Config generated by GPT. Please review and apply."
    }

@app.post("/apply-config")
async def apply_config(
    request: SecureApplyConfigRequest,
    rate_limit: bool = Depends(rate_limit_dependency("api", "config_operations"))
):
    success, message = send_config_to_device(
        ip=request.ip,
        username=request.username,
        password=request.password,
        config=request.config
    )

    if success:
        log_snapshot(SecureSnapshotRequest(
            ip=request.ip,
            username=request.username,
            config=request.config
        ))
        return { "status": "ok", "message": "Configuration applied successfully." }
    else:
        return { "status": "error", "message": message }

@app.post("/log-snapshot")
async def snapshot_handler(
    request: SecureSnapshotRequest,
    rate_limit: bool = Depends(rate_limit_dependency("api", "snapshot_operations"))
):
    return log_snapshot(request)

@app.post("/preview-rollback")
async def preview_handler(request: SecurePreviewRequest):
    return preview_rollback(request)

@app.post("/rollback-latest")
async def rollback_handler(
    request: SecureRollbackRequest,
    rate_limit: bool = Depends(rate_limit_dependency("api", "rollback_operations"))
):
    return rollback_latest(request)

@app.post("/rollback")
async def rollback_fallback(request: SecureRollbackRequest):
    return rollback_latest(request)

@app.post("/run-show-command")
async def run_show(
    request: SecureShowCommandRequest,
    rate_limit: bool = Depends(rate_limit_dependency("api", "device_commands"))
):
    output = run_show_command(request.ip, request.username, request.password, request.command)
    return {"output": output}

@app.post("/ask-ai-show")
async def ask_ai_show(request: SecureAskAIShowRequest):
    command = gpt_generate_show_command(request.question).strip().strip('`')
    try:
        hostname = get_hostname(request.ip, request.username, request.password)
        output = run_show_command(request.ip, request.username, request.password, command)
        return {
            "command": f"{hostname} {command}",
            "output": output
        }
    except Exception:
        return {
            "command": f"{command}",
            "output": f"Failed to execute: {command}\n(This may be due to unreachable host or invalid command.)"
        }

@app.post("/transcribe-audio")
async def transcribe_audio(file: UploadFile = File(...)):
    # Use secure file upload handler
    secure_upload = SecureFileUpload()
    filename, file_hash = await secure_upload.save_upload(file)
    if not WHISPER_AVAILABLE:
        return {"error": "Audio transcription is not available. Please install the whisper package."}
    
    if not AUDIO_PROCESSING_AVAILABLE:
        return {"error": "Audio processing is not available. Please install the pydub package."}
    
    try:
        # Save the uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = temp_file.name

        # Convert to WAV if needed
        audio = AudioSegment.from_file(temp_file_path)
        wav_path = temp_file_path + ".wav"
        audio.export(wav_path, format="wav")

        # Transcribe using Whisper
        model = whisper.load_model("base")
        result = model.transcribe(wav_path)

        # Clean up temporary files
        os.unlink(temp_file_path)
        os.unlink(wav_path)

        return {"text": result["text"]}
    except Exception as e:
        return {"error": str(e)}

app.post("/dialogflow-webhook")(dialogflow_webhook)
app.include_router(websocket_router)

# Add agent WebSocket endpoint directly to main app
@app.websocket("/ws/agent/{agent_token}")
async def agent_websocket(websocket: WebSocket, agent_token: str):
    """WebSocket endpoint for agent connections."""
    try:
        # Get database session directly
        from app.core.database import SessionLocal
        from app.models.base import Agent
        from app.models.base import AgentTokenAuditLog
        from datetime import datetime
        import json
        
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
            try:
                audit = AgentTokenAuditLog(
                    agent_id=agent.id,
                    event_type="websocket_connected",
                    timestamp=datetime.utcnow(),
                    details={}
                )
                db.add(audit)
                db.commit()
            except Exception as e:
                logger.error(f"Error logging agent event: {e}")
            
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
                try:
                    audit = AgentTokenAuditLog(
                        agent_id=agent.id,
                        event_type="websocket_disconnected",
                        timestamp=datetime.utcnow(),
                        details={}
                    )
                    db.add(audit)
                    db.commit()
                except Exception as e:
                    logger.error(f"Error logging agent event: {e}")
                
        finally:
            db.close()
            
    except Exception as e:
        if websocket.client_state.value < 3:  # Not closed yet
            await websocket.close(code=4000, reason=f"Internal error: {str(e)}")
        logger.error(f"WebSocket error: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint for Docker and load balancers"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "cisco-ai-backend"
    }

@app.get("/rate-limit-stats")
async def get_rate_limit_stats(request: Request):
    """Get rate limiting statistics for monitoring"""
    from app.core.simple_rate_limiting import get_rate_limit_stats_simple
    
    client_ip = request.client.host if request.client else "unknown"
    stats = get_rate_limit_stats_working(client_ip)
    
    return {
        "client_ip": client_ip,
        "rate_limit_stats": stats,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/debug/routes")
def list_routes():
    routes = []
    company_token_routes = []
    
    for route in app.routes:
        route_info = {
            "path": route.path,
            "name": route.name,
            "methods": list(route.methods) if hasattr(route, 'methods') else []
        }
        routes.append(route_info)
        
        # Check specifically for company-tokens routes
        if hasattr(route, 'path') and 'company-tokens' in route.path:
            company_token_routes.append(route_info)
    
    return {
        "total_routes": len(routes),
        "company_token_routes": company_token_routes,
        "all_routes": routes
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))  # Cloud Run provides the PORT env variable
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=port)



















