gcloud auth activate-service-account restapi-local@ntnu-student-project.iam.gserviceaccount.com --key-file=/run/secrets/gcp_credentials
gcloud auth activate-service-account scanner@ntnu-student-project.iam.gserviceaccount.com --key-file=/app/key.json
apt-get install ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin


# Gcloud CLI
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
apt-get update && apt-get install -y gcloud-cli

# Install GCR Credential Helper
VERSION=2.0.0
OS=linux  # or "darwin" for OSX, "windows" for Windows.
ARCH=amd64  # or "386" for 32-bit OSs, "arm64" for ARM 64.

# https://cloud.google.com/container-registry/docs/advanced-authentication#standalone-helper
curl -fsSL "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v2.1.1/docker-credential-gcr_linux_amd64-2.1.1.tar.gz" \
| tar xz --to-stdout ./docker-credential-gcr \
> /usr/local/bin/docker-credential-gcr && chmod +x /usr/local/bin/docker-credential-gcr
docker-credential-gcr configure-docker

curl -L "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v2.1.1/docker-credential-gcr_linux_amd64-2.1.1.tar.gz"
cat /run/secrets/gcp_credentials.json | docker login -u _json_key --password-stdin https://gcr.io
docker login -u _json_key -p "$(cat /run/secrets/gcp_credentials.json)" https://gcr.io
