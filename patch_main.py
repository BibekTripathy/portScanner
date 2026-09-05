import re

with open('backend/main.py', 'r') as f:
    content = f.read()

import_patch = """from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os"""

content = content.replace('from fastapi import FastAPI, HTTPException, Depends, status, Header', import_patch)

static_patch = """
# --- FRONTEND (STATIC FILES) ---
frontend_dist = os.path.join(os.path.dirname(__file__), "../frontend/dist")
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
"""

content = content.replace('if __name__ == "__main__":', static_patch)

with open('backend/main.py', 'w') as f:
    f.write(content)
