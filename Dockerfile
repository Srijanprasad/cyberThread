# Multi-stage Dockerfile for CyberThread AI
FROM node:20-alpine AS frontend-builder
WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm install
COPY dashboard/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and built frontend
COPY . .
COPY --from=frontend-builder /app/dashboard/dist ./dashboard/dist

# Ensure models are trained
RUN PYTHONPATH=. python detection/train_models.py

EXPOSE 8000

ENV PYTHONPATH=.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
