FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (dig for DNS block lookups)
RUN apt-get update && apt-get install -y --no-install-recommends dnsutils curl && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application code
COPY app.py config.py database.py auth.py rate_limiter.py ./
COPY routes/ routes/
COPY services/ services/
COPY clients/ clients/
COPY templates/ templates/
COPY static/ static/
COPY scripts/ scripts/
COPY opencanary/ opencanary/

# Create volume mount point for persistent data
RUN mkdir -p /data

ENV SECRET_KEY="change-me-in-production"
ENV DATABASE_PATH="/data/soc_ip_blocker.db"
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "app:create_app()"]
