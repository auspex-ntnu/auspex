FROM python:3.10.4-slim-buster as scanner-requirements

WORKDIR /tmp

# Install poetry and copy poetry files
RUN pip install poetry
COPY ./scanner/pyproject.toml /tmp/

# Copy core module
# Needs to be copied here in order for poetry export to function
COPY ./core/pyproject.toml /core/pyproject.toml

# Generate requirements.txt
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM python:3.10.4-slim-buster

WORKDIR /app
COPY --from=scanner-requirements /tmp/requirements.txt /app/requirements.txt
COPY ./core /core
RUN --mount=type=cache,target=/root/.cache \
    pip install --upgrade -r /app/requirements.txt


COPY ./scanner /app
EXPOSE 80

# Python optimization
ENV PYTHONOPTIMIZE=1

# Environment variable for Scanner app
ENV COLLECTION_SCANS=auspex-scans
ENV BUCKET_SCANS=auspex-scans
ENV GOOGLE_CLOUD_PROJECT=ntnu-student-project

CMD ["uvicorn", "scanner:app", "--host", "0.0.0.0", "--port", "80"]
