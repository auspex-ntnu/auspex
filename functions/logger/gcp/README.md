# Logger (GCP)

Logger is a service that receives results of a scan performed by the Scanner service. Logger stores the scan metadata in Firestore and the scan results (JSON) in a Cloud Storage bucket.

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
    "scan": "<JSON encoded string from scanning tool output>"
    // Schema can be extended by user without making changes to code.
}
```

The function will store any key:value pairs in the firestore collection (with the exception of the scan data itself).

## Output (example)

```json
{
    "image": "vulhub/php:5.4.1-cgi",
    // ID of Firestore document
    "id": "6yh6rPCX7hFgAgUIB2Wo",
     // Timestamp of logging
    "timestamp": 1645787343.142973,
    // URL to file storing output of scanning tool
    "url": "https://storage.googleapis.com/auspex-scans/vulhubphp54.1-cgi_1645787343_142973.json",
    "blob": "vulhubphp5.4.1-cgi_1645787343_142973.json",
    "backend": "snyk",
    "stderr": "",
    "status": "ok"
}
```

## Environment Variables

`BUCKET_NAME`: Name of bucket to store JSON logs in.

`LOGS_COLLECTION_NAME`: Name of Firestore collection to store scan logs in.

`GCP_PROJECT`: Project that function is deployed to. (Automatically set by GCP, but needs to be specified when run locally (?))
