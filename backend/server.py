"""
server.py

Entrypoint for the packaged binary and for the Tauri desktop sidecar.

Flags are translated into the environment variables that settings.py reads, and only
then is the FastAPI app imported -- settings.py resolves the data directory and the
signing key at import time, so configuration has to be in place first.

    portscanner-backend                          # serve on 0.0.0.0:8000, JWT login
    portscanner-backend --port 8080 --open       # and open a browser at it
    portscanner-backend --mode desktop --port 0 --local-token <tok>   # Tauri sidecar

With `--port 0` a free port is chosen by the OS and reported on stdout, which is how
the desktop shell learns where to point the window.
"""

import argparse
import json
import os
import socket
import sys
import threading
import webbrowser


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="portscanner-backend", description="Unified system monitor backend")
    parser.add_argument("--host", default=None, help="interface to bind (default: 127.0.0.1 in desktop mode, 0.0.0.0 otherwise)")
    parser.add_argument("--port", type=int, default=None, help="port to bind, or 0 to pick a free one")
    parser.add_argument("--mode", choices=["server", "desktop"], default=None, help="desktop mode trusts --local-token on loopback")
    parser.add_argument("--local-token", default=None, help="shared secret accepted from loopback clients in desktop mode")
    parser.add_argument("--data-dir", default=None, help="where to keep the database, logs and signing key")
    parser.add_argument("--open", action="store_true", help="open the UI in the default browser once the server is up")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    # Populate the environment before settings.py (and therefore the app) is imported.
    if args.mode:
        os.environ["PORTSCANNER_MODE"] = args.mode
    if args.local_token:
        os.environ["PORTSCANNER_LOCAL_TOKEN"] = args.local_token
    if args.data_dir:
        os.environ["PORTSCANNER_DATA_DIR"] = args.data_dir
    if args.host:
        os.environ["PORTSCANNER_HOST"] = args.host

    port = args.port if args.port is not None else int(os.environ.get("PORTSCANNER_PORT", "8000"))
    if port == 0:
        port = _free_port()
    os.environ["PORTSCANNER_PORT"] = str(port)

    # A frozen binary has no importable module path for its own directory, so make
    # `import settings` / `import main` work the same way they do from source.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    import settings  # noqa: E402  (imported after the environment is configured)
    import uvicorn  # noqa: E402

    from main import app  # noqa: E402

    host = settings.HOST
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{display_host}:{port}"

    # Machine-readable handshake for the desktop shell, plus a human-readable line.
    print(json.dumps({"event": "ready", "url": url, "port": port, "mode": settings.MODE}), flush=True)
    print(f"{settings.APP_NAME} {settings.APP_VERSION} listening on {url} (mode: {settings.MODE})", flush=True)
    print(f"data directory: {settings.DATA_DIR}", flush=True)

    if args.open:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
