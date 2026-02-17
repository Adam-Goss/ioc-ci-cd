FROM python:3.12-slim

WORKDIR /app

# Copy and install dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Copy source code
COPY src/ ./src/

# Copy IOC directory (may be empty initially)
COPY iocs/ ./iocs/ 2>/dev/null || mkdir -p ./iocs/

# Set Python to run in unbuffered mode for better logging
ENV PYTHONUNBUFFERED=1

# Entrypoint
ENTRYPOINT ["python", "-m", "src.cli"]
