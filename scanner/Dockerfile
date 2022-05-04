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

RUN : \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    --no-install-recommends \
    curl apt-transport-https ca-certificates gnupg lsb-release \
    # # Add Docker repository
    # && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    # && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    # # Add Google Cloud repo
    # && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    # && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    # # Install Docker and Gcloud
    # && apt-get update \
    # && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin google-cloud-cli\
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && curl https://static.snyk.io/cli/v1.914.0/snyk-linux -o snyk \
    && chmod +x ./snyk \
    && mv ./snyk /usr/local/bin/ \
    && :

# Install Docker Credential Helper
# RUN : \
#     && curl -fsSL "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v2.1.1/docker-credential-gcr_linux_amd64-2.1.1.tar.gz" \
#     | tar xz --to-stdout ./docker-credential-gcr \
#     > /usr/local/bin/docker-credential-gcr && chmod +x /usr/local/bin/docker-credential-gcr \
#     && docker-credential-gcr configure-docker \
#     && :

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
ENV SNYK_TOKEN_FILE=<YOUR_SNYK_TOKEN_FILE>
ENV COLLECTION_SCANS=auspex-scans
ENV BUCKET_SCANS=auspex-scans
ENV GOOGLE_CLOUD_PROJECT=ntnu-student-project

# CMD ["uvicorn", "scanner:app", "--host", "0.0.0.0", "--port", "80"]
CMD ["/bin/bash", "/app/entrypoint.sh"]
