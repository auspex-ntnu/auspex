# Auspex

## Directory structure

```
.
├── core
│   ├── gcp
│   └── auspex_core
│       └── models
├── reporter
│   ├── reporter
│   └── Dockerfile
├── restapi
│   ├── restapi
│   └── Dockerfile
└── scanner
    ├── scanner
    └── Dockerfile
```

## Building

Running the following command will build all images and run them:

```bash
docker compose build
```

## Running Locally

```bash
docker compose up -d
```

## Environment Variables

Required environment variables in .env or secrets manager:

TODO: list envvars

## Known Issues

This section details known issues and shortcomings of the application. Issues pertaining to each microservice are listed in their own sections.

### Scanner

#### Multiple Google Container Registries

Multiple registries per deployment is not supported. See [scanner/config.yaml](scanner/config.yaml) for more information.

Using the approach outlined in `config.yaml`, we can add multiple key files to the Scanner container deployment, and the scanner will select the appropriate one based on the registry name. These keys should be kept in a Secrets Manager. `config.yaml` outlines 3 possible ways of implementing it.

#### Other Container Registry Providers (Azure, etc.)

The service should be able to handle other container registry providers. We have not researched how to implement this in depth.

##### Azure

Using [this](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-authentication?tabs=azure-cli#az-acr-login-with---expose-token) approach combined with a service hosted on Azure, we could potentially fetch the authentication info from that host? Seems unsafe.

Something like:

```py
import httpx
# Fetch token from our Azure hosted token service
res = httpx.get("https://azure-registry-service.io/token")
password = res.text
# maybe some sort of decryption of res.text here
username = "00000000-0000-0000-0000-000000000000"
cmd = f"snyk container test --username {username} --password {password} myreg.azurecr.io/my-image"
```

It's probably easier and safer to host Auspex on Azure to perform these operations.

#### Repository Scanning

Instead of using individual image names as arguments to the application, one should instead be able to provide a repository name. Optionally also a tag?

So instead of:

```json
{
    "images": ["eu.gcr.io/my-project/image-1:latest", "eu.gcr.io/my-project/image-2:latest"]
}
```

We could instead do:

```json
{
    "repository": "eu.gcr.io/my-project",
    "tag": "latest"
}
```

This should be possible to integrate fairly easily by fetching all images in the repo by using the functionality defined in [core/auspex_core/docker/registry.py](core/auspex_core/docker/registry.py). Further Docker Registry API documentation can be found [here](https://docs.docker.com/registry/spec/api/).

### Reporter

#### Image Tags Not Shown In Report

Due to space constraints, we omitted image tags from the reports

### Core

The core module is not a microservice in itself, but represents shared functionality and datastructures. It is not intended to be run directly, but rather to be used by other microservices.

#### Too Tightly Coupled

During the course of the development, it feels like this module became too coupled with the other microservices, and it is not clear how to break this down. It is helpful to expose the various interfaces that the other microservices use in the API Gateway's docs automatically, but it has lead to a too tight of a coupling between the gateway and the other microservices.
