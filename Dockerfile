FROM python:3.12-slim

WORKDIR /app

# Install system deps for spaCy
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[prod]"

# Download spaCy model at build time (not runtime)
RUN python -m spacy download en_core_web_lg

COPY src/ src/

EXPOSE 8080

CMD ["uvicorn", "pw_redact.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
