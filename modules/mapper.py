import psutil
import yaml
from pathlib import Path
from utils.logger import logger

CONFIG_PATH = Path("config/criticalPorts.yaml")


def load_critical_ports():
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading critical ports file: {e}")
        return {}


def processes_map(port_entries):
    mapped = []
    if not port_entries:
        logger.warning("No port entries")
        return mapped

    critical_ports = load_critical_ports()

    for port in port_entries:
        pid = port.get("pid")
        if not pid:
            port.update(
                {
                    "process_name": "unknown",
                    "process_user": "unknown",
                    "exe_path": None,
                    "cmdline": None,
                    "status": "no_pid",
                }
            )
            port["service_guess"] = get_service_info(port, critical_ports)
            mapped.append(port)
            continue
        try:
            proc = psutil.Process(pid)
            port.update(
                {
                    "process_name": proc.name(),
                    "process_user": proc.username(),
                    "exe_path": proc.exe(),
                    "cmdline": proc.cmdline(),
                    "status": proc.status(),
                    "create_time": proc.create_time(),
                    "cpu_percent": proc.cpu_percent(interval=0.1),
                    "memory_mb": proc.memory_info().rss / 1024 / 1024,
                }
            )
        except psutil.NoSuchProcess:
            logger.debug(f"Process with PID {pid} no longer exists")
            port.update(
                {
                    "process_name": "terminated",
                    "process_user": "unknown",
                    "exe_path": None,
                    "cmdline": None,
                    "status": "terminated",
                }
            )
        except psutil.AccessDenied:
            logger.debug(f"Access denied to process with PID {pid}")
            port.update(
                {
                    "process_name": "access_denied",
                    "process_user": "unknown",
                    "exe_path": None,
                    "cmdline": None,
                    "status": "access_denied",
                }
            )

        except Exception as e:
            logger.error(f"Unexpected error mapping PID {pid}: {e}", exc_info=True)
            port.update(
                {
                    "process_name": "error",
                    "process_user": "unknown",
                    "exe_path": None,
                    "cmdline": None,
                    "status": "error",
                }
            )

        port["service_guess"] = get_service_info(port, critical_ports)
        mapped.append(port)
    logger.info(f"Mapped processes for {len(mapped)} port entries")
    return mapped


def get_process_tree(pid):
    try:
        proc = psutil.Process(pid)
        tree = []
        current = proc
        while current:
            try:
                tree.append(
                    {
                        "pid": current.pid,
                        "name": current.name(),
                        "exe": current.exe() if hasattr(current, "exe") else None,
                    }
                )
                parent = current.parent()
                current = parent if parent else None
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception as e:
                logger.debug(f"error in process tree :{e}")
                break
        return tree
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logger.debug(f"Cannot get process tree for PID {pid}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error getting process tree for PID {pid}: {e}")
        return []


def get_service_info(port_info, common_ports=None):
    if common_ports is None:
        common_ports = {}

    port = port_info.get("port")
    if port in common_ports:
        return common_ports[port]

    process_name = port_info.get("process_name", "").lower()
    if "http" in process_name or "nginx" in process_name or "apache" in process_name:
        return "Web Server"
    elif (
        "mysql" in process_name
        or "mariadb" in process_name
        or "postgres" in process_name
    ):
        return "Database"
    elif "redis" in process_name:
        return "Cache"
    elif "docker" in process_name:
        return "Container app"
    elif "python" in process_name or "python3" in process_name:
        return "Python Application"
    elif "node" in process_name or "npm" in process_name:
        return "Node.js Application"
    elif "java" in process_name:
        return "Java Application"

    return "Unknown Service"
