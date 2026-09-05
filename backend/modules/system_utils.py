import psutil
import time

def get_cpu_info():
    return {
        "total": psutil.cpu_percent(interval=None),
        "per_core": psutil.cpu_percent(interval=None, percpu=True)
    }

def get_memory_info():
    mem = psutil.virtual_memory()
    return {
        "total": mem.total,
        "used": mem.used,
        "available": mem.available,
        "percent": mem.percent
    }

def get_disk_info():
    partitions = psutil.disk_partitions()
    disk_data = []

    for p in partitions:
        try:
            usage = psutil.disk_usage(p.mountpoint)
            disk_data.append({
                "device": p.device,
                "mountpoint": p.mountpoint,
                "total": usage.total,
                "used": usage.used,
                "percent": usage.percent
            })
        except:
            continue

    return disk_data

def get_network_info():
    net = psutil.net_io_counters()
    return {
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv,
        "packets_sent": net.packets_sent,
        "packets_recv": net.packets_recv,
        "errin": net.errin,
        "errout": net.errout,
        "dropin": net.dropin,
        "dropout": net.dropout
    }

def get_uptime():
    return time.time() - psutil.boot_time()