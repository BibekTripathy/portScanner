from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import jwt

# Internal imports
from modules.scanner import scan_listening_ports
from modules.mapper import processes_map
from database import engine, Base, get_db
from modules.system_utils import get_cpu_info, get_memory_info, get_disk_info, get_network_info, get_uptime
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

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
