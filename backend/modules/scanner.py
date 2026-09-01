import psutil
import socket
from utils.logger import logger


def scan_listening_ports():
    results = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_LISTEN:
                continue
            if not conn.laddr or len(conn.laddr) < 2:
                continue
            ip = conn.laddr[0]
            port = conn.laddr[1]
            if conn.type == socket.SOCK_STREAM:
                proto = "TCP"
            elif conn.type == socket.SOCK_DGRAM:
                proto = "UDP"
            else:
                proto = "OTHER"
            ip_str = str(ip)
            if (
                ip_str.startswith("127.")
                or ip_str == "::1"
                or ip_str == "0.0.0.0"
                or ip_str == "::"
            ):
                scope = "localhost"
            else:
                scope = "external"

            try:
                process = psutil.Process(conn.pid) if conn.pid else None
                process_name = process.name() if process else "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "Unknown"

            results.append(
                {
                    "protocol": proto,
                    "port": port,
                    "ip": ip_str,
                    "scope": scope,
                    "pid": conn.pid,
                    "process_name": process_name,
                }
            )

        logger.info(f"Discovered {len(results)} listening ports")

    except Exception as e:
        logger.error(f"Error scanning ports: {e}", exc_info=True)
        return []

    return results


def is_port_open(port, protocol="tcp"):
    sock = None
    try:
        if protocol.lower() == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", port))
            return result == 0
        else:
            return False
    except Exception as e:
        logger.debug(f"Check port {port}/{protocol} failed: {e}")
        return False
    finally:
        if sock:
            sock.close()
