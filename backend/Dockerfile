# backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Copy entire repo so analyzer/ is available alongside backend/
COPY . /app/

# Install backend dependencies
RUN pip install --no-cache-dir -r backend/requirements.txt

# Repo root on PYTHONPATH so `import analyzer` and `import backend` resolve
ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
