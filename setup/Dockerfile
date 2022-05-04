FROM python:3.10.4-slim-buster as setup-requirements

WORKDIR /tmp

# Install poetry and copy poetry files
RUN pip install poetry
COPY ./setup/pyproject.toml /tmp/

# Copy core module
# Needs to be copied here in order for poetry export to function
# COPY ./core/pyproject.toml /core/pyproject.toml

# Generate requirements.txt
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes


FROM python:3.10.4-slim-buster

RUN : \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    --no-install-recommends \
    apt-transport-https ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && :


WORKDIR /app
COPY --from=setup-requirements /tmp/requirements.txt /app/requirements.txt
# COPY ./core /core
RUN --mount=type=cache,target=/root/.cache \
    pip install --upgrade -r /app/requirements.txt
COPY ./setup /app


CMD ["python", "main.py"]
