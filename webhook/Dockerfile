FROM python:3.12-slim

# Security: run as non-root user
RUN groupadd -r webhook && useradd -r -g webhook webhook

WORKDIR /app

# Copy and install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py responder.py ./

# Security: non-root ownership, read-only where possible
RUN chown -R webhook:webhook /app

USER webhook

EXPOSE 5000

CMD ["python3", "app.py"]