from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
import jwt

# Internal imports
from modules.scanner import scan_listening_ports
from modules.mapper import processes_map
from database import engine, Base, get_db
from modules.system_utils import get_cpu_info, get_memory_info, get_disk_info, get_network_info, get_uptime
from modules.process_service import process_service
from modules.docker_service import docker_service
import models
import auth
import uvicorn

# Create the database tables if they don't exist
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Unified Monitor API", description="API for monitoring ports and system stats")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 setup: This tells FastAPI where the client should go to get a token.
# It makes the Swagger UI (/docs) automatically support an "Authorize" button.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

# --- AUTHENTICATION DEPENDENCY ---
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    This function acts as a guard/bouncer. 
    Any endpoint that has this as a dependency will REQUIRE a valid token.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the token using our secret key
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
        
    # Check if the user actually exists in the database
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


# --- PUBLIC ENDPOINTS ---

@app.post("/api/register")
def register_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Registers a new user. We use OAuth2PasswordRequestForm for standard compatibility.
    It expects 'username' and 'password' in the request body (form-data).
    """
    # Check if user already exists
    existing_user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
        
    # Hash the password and save to DB
    hashed_password = auth.get_password_hash(form_data.password)
    new_user = models.User(username=form_data.username, hashed_password=hashed_password)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"msg": f"User {new_user.username} successfully created!"}

@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Verifies credentials and issues a JWT token.
    """
    # Find user in DB
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    
    # Check if user exists and password is correct
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # Valid credentials! Create the token.
    access_token = auth.create_access_token(data={"sub": user.username})
    
    return {"access_token": access_token, "token_type": "bearer"}


# --- PROTECTED ENDPOINTS ---

@app.get("/api/scan")
def get_scan_results(current_user: models.User = Depends(get_current_user)):
    """
    This endpoint is protected! Notice the `Depends(get_current_user)` parameter.
    If the request doesn't have a valid JWT token, FastAPI will block it before 
    it even reaches this code.
    """
    try:
        raw_ports = scan_listening_ports()
        if not raw_ports:
            return {"status": "success", "data": [], "message": "No listening ports found"}
        
        mapped_ports = processes_map(raw_ports)
        return {"status": "success", "data": mapped_ports, "total": len(mapped_ports)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/metrics")
def get_system_metrics(current_user: models.User = Depends(get_current_user)):
    """
    Returns full system stats (CPU, Memory, Disk, Network, Uptime)
    Requires valid JWT authentication.
    """
    try:
        data = {
            "cpu": get_cpu_info(),
            "memory": get_memory_info(),
            "disk": get_disk_info(),
            "network": get_network_info(),
            "uptime": get_uptime()
        }
        return {"status": "success", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/processes")
def get_processes(limit: int = 50, current_user: models.User = Depends(get_current_user)):
    try:
        data = process_service.list_processes(limit)
        return {"status": "success", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/processes/{pid}/kill")
def kill_proc(pid: int, current_user: models.User = Depends(get_current_user)):
    try:
        success, msg = process_service.kill_process(pid)
        if success:
            return {"status": "success", "message": msg}
        else:
            raise HTTPException(status_code=500, detail=msg)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/docker/containers")
def get_docker_containers(current_user: models.User = Depends(get_current_user)):
    try:
        data = docker_service.list_containers()
        return {"status": "success", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class DockerActionRequest(BaseModel):
    action: str

@app.post("/api/docker/containers/{container_id}/control")
def control_docker_container(container_id: str, req: DockerActionRequest, current_user: models.User = Depends(get_current_user)):
    try:
        success, msg = docker_service.control_container(container_id, req.action)
        if success:
            return {"status": "success", "message": msg}
        else:
            raise HTTPException(status_code=500, detail=msg)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/docker/containers/{container_id}/logs")
def get_docker_logs(container_id: str, tail: int = 100, current_user: models.User = Depends(get_current_user)):
    try:
        logs = docker_service.get_container_logs(container_id, tail=tail)
        return {"status": "success", "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# --- FRONTEND (STATIC FILES) ---
import sys
if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
    frontend_dist = os.path.join(base_dir, "frontend", "dist")
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    frontend_dist = os.path.join(base_dir, "..", "frontend", "dist")

if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")
    
    @app.get("/{full_path:path}")
    def serve_frontend(full_path: str):
        # Allow API calls to 404 naturally
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")
            
        file_path = os.path.join(frontend_dist, full_path)
        if full_path and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))

if __name__ == "__main__":

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
