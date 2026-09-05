import docker
from flask import current_app

class DockerService:
    def __init__(self):
        self.client = None

    def get_client(self):
        if self.client:
            try:
                self.client.ping()
                return self.client
            except Exception:
                self.client = None
        
        try:
            self.client = docker.from_env()
            self.client.ping()  # Verify connection
            return self.client
        except Exception as e:
            print(f"Docker connection error: {e}")
            self.client = None
            return None

    def list_containers(self, all=True):
        client = self.get_client()
        if not client:
            return []
        
        containers = client.containers.list(all=all)
        return [
            {
                "id": c.short_id,
                "name": c.name,
                "status": c.status,
                "image": c.image.tags[0] if c.image.tags else "unknown",
                "state": c.attrs.get('State', {})
            } for c in containers
        ]

    def manage_container(self, container_id, action):
        client = self.get_client()
        if not client:
            return False, "Docker client not available"
        
        try:
            container = client.containers.get(container_id)
            if action == "start":
                container.start()
            elif action == "stop":
                container.stop()
            elif action == "restart":
                container.restart()
            elif action == "remove":
                container.remove(force=True)
            else:
                return False, f"Invalid action: {action}"
            return True, f"Container {action}ed successfully"
        except Exception as e:
            return False, str(e)

    def get_container_logs(self, container_id, tail=100):
        client = self.get_client()
        if not client:
            return None
        
        try:
            container = client.containers.get(container_id)
            logs = container.logs(tail=tail).decode('utf-8')
            return logs
        except Exception as e:
            return f"Error fetching logs: {str(e)}"

    def close(self):
        """Close the Docker client connection pool."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

docker_service = DockerService()
