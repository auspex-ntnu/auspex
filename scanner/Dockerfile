FROM python:3.10-slim as scanner-requirements

WORKDIR /tmp
RUN pip install poetry 
COPY ./pyproject.toml ./poetry.lock* /tmp/
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM python:3.10-slim

ENV SNYK_TOKEN=<TOKEN>
ENV USER_ID=1234
RUN : \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    --no-install-recommends \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && curl https://static.snyk.io/cli/v1.848.0/snyk-linux -o snyk \
    && chmod +x ./snyk \
    && mv ./snyk /usr/local/bin/ \
    && :

WORKDIR /app
COPY --from=scanner-requirements /tmp/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY ./* /app
EXPOSE 80

CMD ["/bin/bash"]