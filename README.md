# Unified System Monitor & Port Scanner

A comprehensive, full-stack monitoring solution for keeping track of your system's resources, active processes, Docker containers, and network ports.

## 🚀 Features Currently Available

- **System Metrics Dashboard:** Real-time monitoring of CPU, RAM, Disk, and Network usage.
- **Advanced Process Explorer:** 
  - View all active processes with per-process CPU and Memory usage.
  - Sort by PID, Name, User, CPU, or Memory.
  - Instantly kill unresponsive or suspicious processes directly from the UI.
- **Docker Management:**
  - View all running and stopped Docker containers.
  - Start, stop, restart, or remove containers.
  - View real-time logs for any container.
- **Network Port Scanner:** Scan and map listening ports to their active processes and users.
- **Modern UI/UX:** A fully responsive, dual-theme (Light/Dark) web interface built with React, Vite, and Tailwind CSS.
- **Secure Backend:** FastAPI-powered backend with JWT authentication to keep your monitoring secure.
- **Docker Ready:** Fully containerized architecture. You can easily deploy this tool onto any server using Docker.

## 🛠️ Installation & Deployment

The application is containerized and available on the GitHub Container Registry. You can deploy it easily using Docker Compose or Dockge:

```yaml
version: '3.8'

services:
  system-monitor:
    image: ghcr.io/bibektripathy/portscanner:latest
    container_name: system-monitor
    restart: unless-stopped
    ports:
      - "8000:8000"
    pid: "host"
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
```

After deploying, simply visit `http://<your-server-ip>:8000` in your browser.

## 🗺️ Future Roadmap

We are actively working on expanding the capabilities of this tool! Upcoming features include:
- **Multi-Server Monitoring:** The ability to connect to and monitor multiple servers from a single centralized dashboard.
- **Mobile Application:** A dedicated mobile app for monitoring your infrastructure on the go.

## Development

To run the project locally for development:
1. **Backend:** `cd backend && pip install -r requirements.txt && uvicorn main:app --reload`
2. **Frontend:** `cd frontend && npm install && npm run dev`
