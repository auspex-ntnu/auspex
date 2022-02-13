FROM python:3.10-slim as reporter-requirements

WORKDIR /tmp

# Install poetry and copy poetry files
RUN pip install poetry 
COPY ./reporter/pyproject.toml ./reporter/poetry.lock* /tmp/

# Copy core module
COPY ./core /core

# Generate requirements.txt
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM texlive/texlive:latest

# Install Python + Pip
RUN : \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    --no-install-recommends \
    python3 python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && :

WORKDIR /app

# Copy dependencies from poetry stage
COPY --from=reporter-requirements /tmp/requirements.txt /app/requirements.txt
COPY --from=reporter-requirements /core /core
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY ./reporter /app
EXPOSE 80
CMD ["uvicorn", "reporter.main:app", "--host", "0.0.0.0", "--port", "80"]