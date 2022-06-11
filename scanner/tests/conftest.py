# Set up environment variables
import os

os.environ["URL_SCANNER_SNYK"] = "http://localhost:5000"  # TODO: change
os.environ["COLLECTION_SCANS"] = "auspex-scans"
os.environ["BUCKET_SCANS"] = "auspex-scans"
os.environ["TIMEOUT_SCANNER"] = "600"
