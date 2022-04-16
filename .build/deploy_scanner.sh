gcloud run deploy scanner \
--image=gcr.io/ntnu-student-project/auspex/scanner \
--allow-unauthenticated \
--service-account=1091840394515-compute@developer.gserviceaccount.com \
--concurrency=1 \
--set-env-vars=COLLECTION_SCANS=auspex-scans,BUCKET_SCANS=auspex-scans,GOOGLE_CLOUD_PROJECT=ntnu-student-project \
--set-secrets=/run/secrets/SNYK_TOKEN_FILE=SNYK_TOKEN:latest \
--platform=managed \
--region=europe-north1 \
--project=ntnu-student-project
