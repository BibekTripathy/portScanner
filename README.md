# Unified System Monitor & Port Scanner

Monitor CPU, memory, disk, network, processes, Docker containers and listening ports —
on the machine in front of you, or on any server you have deployed it to, from the same
window.

It ships three ways, all from one codebase:

| How you run it | What it is | Login |
| --- | --- | --- |
| **Desktop app** (Linux, Windows) | A native window that starts its own backend on loopback | None — you are already at the machine |
| **Docker container** | The web UI and API on a server, reachable at `http://<server>:8000` | Username + password (JWT) |
| **Headless binary** | A single file that serves the same web UI, for a box without Docker | Username + password (JWT) |

The desktop app can also **add servers by address** and switch between them from the
header, so one window covers your laptop and your boxes.

## 🚀 Features

- **System metrics** — real-time CPU (total and per core), RAM, disk and network I/O.
- **Process explorer** — every process with per-process CPU and memory, sortable by
  PID, name, user, CPU or memory, and killable from the UI.
- **Docker management** — list running and stopped containers, start/stop/restart/remove
  them, and tail their logs.
- **Port scanner** — listening TCP/UDP ports mapped to the owning process, user,
  executable and a best-guess service name.
- **Multi-machine** — a target switcher in the header. Your own machine is always there;
  add servers with their IP and they are remembered, each with its own login.
- **Modern UI** — responsive, light/dark, React + Vite + Tailwind.
- **Secure backend** — FastAPI with bcrypt password hashing and JWT sessions. The signing
  key is generated per install, never hardcoded.

## 💻 Desktop app

Grab the installer for your platform from the
[latest release](https://github.com/BibekTripathy/portScanner/releases):

- **Linux** — `.deb`, `.rpm` or `.AppImage`
- **Windows** — `.msi` or the `.exe` installer

The app is a [Tauri](https://tauri.app) shell that starts the Python backend as a
bundled sidecar on a random loopback port, with a token generated at launch. Nothing
listens on your network, and there is no login screen for your own machine. Closing
the window stops the backend.

Your database, generated signing key and logs live in:

- Linux: `~/.local/share/portScanner/`
- Windows: `%APPDATA%\portScanner\`

> Some readings need privileges. Process names and executables for ports owned by
> other users show as `access_denied` unless the app is run with elevated rights, and
> Docker management needs your user to be able to reach the Docker socket.

## 🐳 Deploy on a server

```yaml
services:
  system-monitor:
    image: ghcr.io/bibektripathy/portscanner:latest
    container_name: system-monitor
    restart: unless-stopped
    ports:
      - "8000:8000"
    pid: "host"
    privileged: true
    environment:
      # Optional, but recommended: otherwise a key is generated into the volume.
      # PORTSCANNER_SECRET_KEY: "a-long-random-string"
      PORTSCANNER_DATA_DIR: /data
    volumes:
      - monitor-data:/data            # accounts + signing key; keep this
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro

volumes:
  monitor-data:
```

Then either open `http://<your-server-ip>:8000` in a browser, or add that address in
the desktop app under **Servers → Add a server**. Register the first account on the
login screen.

> `privileged` and `pid: host` are what let the container report on the host rather
> than on itself. Treat the port as admin-only: it can kill processes and control
> containers. Put it behind a VPN or a reverse proxy with TLS rather than exposing it
> to the internet.

### Headless binary

For a server without Docker, download `portScanner-linux` (or `portScanner-windows.exe`)
from the release and run it:

```bash
./portScanner-linux                 # http://0.0.0.0:8000
./portScanner-linux --port 9000     # a different port
./portScanner-linux --open          # and open a browser at it
./portScanner-linux --help          # all flags
```

### Configuration

Both the container and the binary read:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORTSCANNER_SECRET_KEY` | generated into the data dir | JWT signing key |
| `PORTSCANNER_DATA_DIR` | per-user app data dir | database, key and logs |
| `PORTSCANNER_HOST` | `0.0.0.0` | interface to bind |
| `PORTSCANNER_PORT` | `8000` | port to bind |

## 🛠️ Development

```bash
# Backend  (http://localhost:8000)
cd backend && pip install -r requirements.txt && uvicorn main:app --reload

# Frontend (http://localhost:5173, talks to :8000)
cd frontend && npm install && npm run dev

# Desktop app, against the Vite dev server with hot reload
cd desktop && npm install
npm run sidecar     # freeze the backend into src-tauri/binaries/ (needs pyinstaller)
npm run dev

# Desktop installers for the current platform
cd desktop && npm run sidecar && npm run build
```

Linux needs Tauri's prerequisites for the desktop build (`webkit2gtk-4.1`, `gtk3`,
`librsvg`, `patchelf`); see [tauri.app/start/prerequisites](https://tauri.app/start/prerequisites/).

### How it fits together

```
frontend/            React UI. One build serves all three shells.
  services/
    connections.js   the target list (this machine + saved servers) and active target
    transport.js     HTTP, through Rust in the desktop app, fetch in the browser
    api.js           endpoints, always aimed at the active target
backend/
  server.py          entrypoint for the binary and the sidecar (CLI flags)
  main.py            FastAPI app, also importable as `main:app`
  settings.py        data dir, signing key, desktop-vs-server rules
desktop/
  src-tauri/         the Tauri shell: spawns the sidecar, proxies HTTP
  scripts/           PyInstaller sidecar build
```

In the desktop app the UI's HTTP requests are made from Rust, not the webview. A
webview is a secure context, so it would refuse plain-HTTP calls to a server on your
LAN as mixed content — which is exactly what monitoring a remote machine needs.

## 🗺️ Roadmap

- Historical metrics rather than only live readings
- Alerting when a watched port or container changes state
- A mobile client reusing the same API
