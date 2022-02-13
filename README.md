# Auspex

## Directory structure

```
.
├── auspex_core
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
