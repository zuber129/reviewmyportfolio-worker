# RQ Worker Dockerfile
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and health scripts
COPY app/ ./app/
COPY scripts/ ./scripts/

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV LOG_LEVEL=INFO
ENV ENVIRONMENT=production

# RQ worker command
CMD ["rq", "worker", "--with-scheduler", "--url", "${REDIS_URL}", "--max-jobs", "100", "pdf_parsing", "portfolio_processing"]
