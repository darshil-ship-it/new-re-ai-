# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better Docker caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

# Railway provides the PORT environment variable
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Start Flask application with Gunicorn
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"]