FROM python:3.12-slim

WORKDIR /app

# Copy project files and install dependencies
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# Set Python to run in unbuffered mode for better logging
ENV PYTHONUNBUFFERED=1

# GitHub Actions mounts the workspace at /github/workspace
# IOC files are accessed from there at runtime

ENTRYPOINT ["python", "-m", "src.cli"]
