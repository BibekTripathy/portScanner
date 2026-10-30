# Stage 1: Build Frontend
FROM node:20-alpine AS build-stage
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Setup Python Backend
FROM python:3.11-slim
WORKDIR /app

# Build dependencies for python packages like psutil
RUN apt-get update && apt-get install -y --no-install-recommends gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy built frontend
COPY --from=build-stage /app/frontend/dist ./frontend/dist

# Copy backend source
COPY backend/ ./backend/

WORKDIR /app/backend

# The database, generated JWT signing key and logs live here. Mount it as a volume to
# keep your accounts across container upgrades (see docker-compose.yml).
ENV PORTSCANNER_DATA_DIR=/data \
    PORTSCANNER_MODE=server \
    PORTSCANNER_HOST=0.0.0.0 \
    PORTSCANNER_PORT=8000
VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/info', timeout=4).status==200 else 1)"

# server.py honours PORTSCANNER_* and prints the resolved address on startup.
CMD ["python", "server.py"]
