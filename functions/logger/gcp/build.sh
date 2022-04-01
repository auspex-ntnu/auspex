#!/bin/bash

# Builds and deploys the Logger service.

# Export up-to-date requirements.txt
poetry export -f requirements.txt -o requirements.txt --without-hashes


# This should be defined somewhere else
gcloud config set project ntnu-student-project
gcloud config set compute/region europe-north1
gcloud config set compute/zone europe-north1-a

# DOCS: https://cloud.google.com/sdk/gcloud/reference/functions/deploy
gcloud functions deploy auspex_logger \
    --runtime python39 \
    --trigger-http \
    --allow-unauthenticated \
    --entry-point handle_request \
    --env-vars-file .env.yaml