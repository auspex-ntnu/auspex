# Utilizing multi stage builds to automatically generate requirements from Poetry
# source: https://fastapi.tiangolo.com/deployment/docker/#docker-image-with-poetry
FROM python:3.10-slim as restapi-requirements

WORKDIR /tmp
RUN pip install poetry 
COPY ./pyproject.toml ./poetry.lock* /tmp/
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

# Build application using generated requirements
FROM python:3.10-slim

WORKDIR /code
COPY --from=restapi-requirements /tmp/requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copy application code and run application
COPY ./ /code
CMD ["uvicorn", "restapi:app", "--host", "0.0.0.0", "--port", "80"]
