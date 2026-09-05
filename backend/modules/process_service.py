import time
import psutil

class ProcessService:
    def __init__(self):
        self._primed = False

    def list_processes(self, limit=50):
        if not self._primed:
            # Prime CPU data (first pass)
            for p in psutil.process_iter(['pid']):
                try:
                    p.cpu_percent(interval=None)
                except:
                    continue
            time.sleep(0.5)
            self._primed = True

        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Sort by CPU usage and limit
        processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        return processes[:limit]

    def kill_process(self, pid):
        try:
            process = psutil.Process(pid)
            process.terminate() # Or process.kill() for forceful
            return True, f"Process {pid} terminated"
        except psutil.NoSuchProcess:
            return False, "Process not found"
        except psutil.AccessDenied:
            return False, "Permission denied"
        except Exception as e:
            return False, str(e)

process_service = ProcessService()
