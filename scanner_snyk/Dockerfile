FROM python:3.10.4-slim-buster as scanner-snyk-requirements

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

RUN : \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    --no-install-recommends \
    curl apt-transport-https ca-certificates gnupg lsb-release \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && curl https://static.snyk.io/cli/v1.933.0/snyk-linux -o snyk \
    && chmod +x ./snyk \
    && mv ./snyk /usr/local/bin/ \
    && :

WORKDIR /app
COPY --from=scanner-snyk-requirements /tmp/requirements.txt /app/requirements.txt
COPY ./core /core
RUN --mount=type=cache,target=/root/.cache \
    pip install --upgrade -r /app/requirements.txt


COPY ./scanner /app
EXPOSE 80

# Python optimization
ENV PYTHONOPTIMIZE=1

# Environment variable for Scanner app
ENV SNYK_TOKEN_FILE=<YOUR_SNYK_TOKEN_FILE>
ENV GOOGLE_CLOUD_PROJECT=ntnu-student-project

CMD ["/bin/bash", "/app/entrypoint.sh"]
