FROM python:3.10-slim as reporter-requirements

WORKDIR /tmp
RUN pip install poetry 
COPY ./pyproject.toml ./poetry.lock* /tmp/
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes


FROM texlive/texlive:latest

RUN : \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    --no-install-recommends \
    python3 python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && :
WORKDIR /app
COPY --from=reporter-requirements /tmp/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY ./* /app
EXPOSE 80
CMD ["/bin/bash"]