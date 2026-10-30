"""
settings.py

Runtime configuration for the backend. The same code runs in three shapes:

  * `desktop`  - launched as a sidecar by the Tauri shell. Binds loopback only and
                 trusts a one-shot token handed to it on startup, so the desktop UI
                 does not have to show a login screen for the machine you are sat at.
  * `server`   - the Docker image / bare-metal deployment. JWT login is mandatory.
  * `dev`      - `uvicorn main:app --reload` during development, behaves like `server`.

Everything here is driven by environment variables so that the Tauri shell, the
Dockerfile and the dev workflow can each configure the process without CLI parsing
having to happen before the FastAPI app is imported.
"""

import os
import platform
import secrets
import shutil
import sys
from pathlib import Path

APP_NAME = "portScanner"
APP_VERSION = "1.1.1"

# `desktop` is only ever set by the Tauri shell; anything else defaults to server rules.
MODE = os.environ.get("PORTSCANNER_MODE", "server").lower()
IS_DESKTOP = MODE == "desktop"
IS_FROZEN = getattr(sys, "frozen", False)


def _default_data_dir() -> Path:
    """Per-user writable location for the database, generated secret and logs."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return Path(base) / APP_NAME


DATA_DIR = Path(os.environ.get("PORTSCANNER_DATA_DIR") or _default_data_dir())
DATA_DIR.mkdir(parents=True, exist_ok=True)

LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "portscanner.db"

# Older versions kept the database next to the source tree. Carry it over once so
# existing accounts survive the move to a proper per-user data directory.
_legacy_db = Path(__file__).resolve().parent / "portscanner.db"
if _legacy_db.is_file() and not DB_PATH.exists():
    try:
        shutil.copy2(_legacy_db, DB_PATH)
    except OSError:
        pass


def _load_secret_key() -> str:
    """
    The JWT signing key. Supplied by the environment in a deployment, otherwise
    generated once and persisted with owner-only permissions.
    """
    env_key = os.environ.get("PORTSCANNER_SECRET_KEY")
    if env_key:
        return env_key

    key_file = DATA_DIR / "secret.key"
    if key_file.is_file():
        existing = key_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing

    generated = secrets.token_urlsafe(48)
    key_file.write_text(generated, encoding="utf-8")
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return generated


SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # one week

# Shared secret for the desktop shell. Only honoured for loopback requests.
LOCAL_TOKEN = os.environ.get("PORTSCANNER_LOCAL_TOKEN") or None

HOST = os.environ.get("PORTSCANNER_HOST", "127.0.0.1" if IS_DESKTOP else "0.0.0.0")
PORT = int(os.environ.get("PORTSCANNER_PORT", "8000"))

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def describe() -> dict:
    """Public, unauthenticated description of this instance (see `GET /api/info`)."""
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "mode": MODE,
        "hostname": platform.node(),
        "platform": sys.platform,
        "system": platform.system(),
        "release": platform.release(),
        "auth_required": not IS_DESKTOP,
    }
