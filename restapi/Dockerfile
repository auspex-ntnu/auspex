# Utilizing multi stage builds to automatically generate requirements from Poetry
# source: https://fastapi.tiangolo.com/deployment/docker/#docker-image-with-poetry
FROM python:3.10-slim as restapi-requirements

WORKDIR /tmp

# Install poetry and copy poetry files
RUN pip install poetry 
COPY ./restapi/pyproject.toml /tmp/
# TODO: find out why lock file won't work
# COPY ./restapi/pyproject.toml ./reporter/poetry.lock* /tmp/

# Copy core module
COPY ./core /core

# Generate requirements.txt
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

# Build application using generated requirements
FROM python:3.10-slim

WORKDIR /app

# Copy dependencies from poetry stage
COPY --from=restapi-requirements /tmp/requirements.txt /app/requirements.txt
COPY --from=restapi-requirements /core /core
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

# Copy application code and run application
COPY ./restapi /app
CMD ["uvicorn", "restapi:app", "--host", "0.0.0.0", "--port", "80"]
