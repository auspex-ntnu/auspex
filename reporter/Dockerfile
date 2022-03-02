FROM python:3.10-slim as reporter-requirements

WORKDIR /tmp

# Install poetry and copy poetry files
RUN pip install poetry 
COPY ./reporter/pyproject.toml /tmp/

# Copy core module
COPY ./core/pyproject.toml /core/pyproject.toml

# Generate requirements.txt
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM texlive/texlive:latest

# Install Python + Pip
RUN : \
    # && apt-get remove -y python3 python3.9 \
    && apt-get update \
    # && apt install software-properties-common curl -y \
    # && add-apt-repository ppa:deadsnakes/ppa \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    --no-install-recommends \
    python3-pip\
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    # && curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10 \
    && :

WORKDIR /app

# Copy dependencies from poetry stage
COPY --from=reporter-requirements /tmp/requirements.txt /app/requirements.txt
# COPY --from=reporter-requirements /core /core
COPY ./core /core
# RUN python3.10 -m pip install --no-cache-dir --upgrade -r /app/requirements.txt
RUN --mount=type=cache,target=/root/.cache \
    pip install --upgrade -r /app/requirements.txt

COPY ./reporter /app
EXPOSE 80
CMD ["uvicorn", "reporter.main:app", "--host", "0.0.0.0", "--port", "80"]