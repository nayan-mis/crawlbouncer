# Build from the repo root:  docker build -f backend/Dockerfile -t crawlbouncer .

# Stage 1: build the React dashboard
FROM node:22-slim AS frontend-build
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: the application
FROM python:3.12-slim

# curl: healthcheck. dnsutils: `dig`, used to verify CNAME records.
RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app/ ./app/
COPY backend/run.py .
COPY web/ ./web/
COPY --from=frontend-build /frontend/dist/ ./frontend/dist/

# SQLite lives here; mount a volume on /app/data to keep it across restarts.
RUN mkdir -p /app/data

# Run as a normal, unprivileged user (no docker socket, no extra groups).
RUN useradd -r -s /bin/false crawlbouncer && chown -R crawlbouncer:crawlbouncer /app
USER crawlbouncer

ENV SQLITE_PATH=/app/data/crawlbouncer.db
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "run.py"]
