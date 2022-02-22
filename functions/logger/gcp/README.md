# Logger (GCP)

## Input

Method: `POST`

Payload:

```
Content-Type: multipart/form-data
form-data:
    image: "<IMAGE_NAME>"
    started: 12345.6789
    scan: snyk_json_output.json
```

## Environment Variables

`BUCKET_NAME`: Name of bucket to store JSON logs

`COLLECTION_NAME`: Name of Firestore collection to store scan logs

`GCP_PROJECT`: Project that function is deployed to. (Automatically set by GCP, but needs to be specified when run locally (?))
