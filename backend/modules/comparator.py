import json
from utils.logger import logger


def load_scan_from_file(filename):
    try:
        with open(filename, "r") as f:
            data = json.load(f)
            if isinstance(data, dict) and "ports" in data:
                return data["ports"]
            elif isinstance(data, list):
                return data
            else:
                logger.error(f"Invalid JSON format in {filename}")
                return None
    except Exception as e:
        logger.error(f"Failed to load baseline scan {filename}: {e}")
        return None


def compare_scans(baseline, current):
    if baseline is None:
        baseline = []
    if current is None:
        current = []

    base_map = {(p["protocol"], p["port"]): p for p in baseline}
    curr_map = {(p["protocol"], p["port"]): p for p in current}

    base_keys = set(base_map.keys())
    curr_keys = set(curr_map.keys())

    added = [curr_map[k] for k in curr_keys - base_keys]
    removed = [base_map[k] for k in base_keys - curr_keys]
    changed = []
    for k in base_keys & curr_keys:
        b_proc = base_map[k].get("process_name", "Unknown")
        c_proc = curr_map[k].get("process_name", "Unknown")
        if b_proc != c_proc:
            changed.append(
                {
                    "port": k[1],
                    "protocol": k[0],
                    "old_process": b_proc,
                    "new_process": c_proc,
                }
            )

    return added, removed, changed
