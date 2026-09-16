# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Set environment variables
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
# Default port to 8000, but Railway will automatically override this with its own $PORT
ENV PORT=8000

# Expose the port (using the environment variable)
EXPOSE ${PORT}

# Run the application with gunicorn, binding to the dynamic PORT variable
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"]