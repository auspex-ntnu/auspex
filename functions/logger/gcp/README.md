# Logger (GCP)

## Input

Method: `POST`

Content-type: `application/json`

Body:

```json
{
    "image": "vulhub/php:5.4.1-cgi",
    "backend": "snyk",
    "status": "ok",
    "stderr": "",
    "scan": "<JSON encoded string from scanning software output>"
    // Schema can be extended by user without making changes to code.
}
```

The function will store any key:value pairs in the firestore collection (with the exception of the scan data itself).

## Output (example)

```json
{
    "image": "vulhub/php:5.4.1-cgi",
    "id": "DDTZ7usJZC4dlE0qbKZq",
    "timestamp": 1645541989.5863428,
    "url": "https://storage.googleapis.com/auspex-scans/vulhubphp5.4.1-cgi_1645541989_5863428.json.json",
    "score": "9.4",
    "backend": "snyk",
    "started": "1644836960.12491414",
    "stderr": "",
    "status": "ok",
    "finished": "1644836970.1921491294"
}
```

## Environment Variables

`BUCKET_NAME`: Name of bucket to store JSON logs in.

`COLLECTION_NAME`: Name of Firestore collection to store scan logs in.

`GCP_PROJECT`: Project that function is deployed to. (Automatically set by GCP, but needs to be specified when run locally (?))
