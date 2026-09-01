from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from modules.scanner import scan_listening_ports
from modules.mapper import processes_map
import uvicorn

app = FastAPI(title="PortScanner API", description="API for scanning and mapping network ports")

# Allow CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for now. Can be restricted later.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Welcome to the PortScanner API. Visit /docs for the API documentation."}

@app.get("/api/scan")
def get_scan_results():
    try:
        raw_ports = scan_listening_ports()
        if not raw_ports:
            return {"status": "success", "data": [], "message": "No listening ports found"}
        
        mapped_ports = processes_map(raw_ports)
        return {"status": "success", "data": mapped_ports, "total": len(mapped_ports)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
