# Stage 1: Build Frontend
FROM node:20-alpine AS build-stage
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Setup Python Backend
FROM python:3.11-slim
WORKDIR /app

# Install build dependencies for python packages like psutil
RUN apt-get update && apt-get install -y gcc python3-dev && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY backend/requirements.txt ./backend/
# Ensure we have uvicorn and psutil etc
RUN pip install --no-cache-dir -r backend/requirements.txt uvicorn

# Copy built frontend
COPY --from=build-stage /app/frontend/dist ./frontend/dist

# Copy backend source
COPY backend/ ./backend/

WORKDIR /app/backend

# Expose the API port
EXPOSE 8000

# Start Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
