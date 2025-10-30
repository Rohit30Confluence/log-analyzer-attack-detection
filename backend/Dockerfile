FROM python:3.11-slim

WORKDIR /app
COPY backend/ /app/

RUN pip install --no-cache-dir fastapi uvicorn redis pydantic

EXPOSE 8000

# Redirect Uvicorn logs to stdout
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info", "--use-colors", "--no-access-log"]

