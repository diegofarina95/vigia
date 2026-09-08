# --- Stage 1: build the frontend ---------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-fund --no-audit
COPY frontend/ ./
RUN npm run build

# --- Stage 2: Python runtime --------------------------------------------
FROM python:3.12-slim
WORKDIR /app

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./
COPY --from=frontend /build/dist /app/static

ENV FRONTEND_DIST=/app/static \
    VIGIA_DATA_DIR=/app/data \
    VIGIA_PORT=8110

EXPOSE 8110
CMD ["gunicorn", "--bind", "0.0.0.0:8110", "--workers", "2", "--timeout", "120", "app:app"]
