#!/bin/bash

set -euxo pipefail

image=$1

if [[ -z $image ]]; then
    echo "Usage: scan.sh <IMAGE>"
    exit 1
fi

filename=$(echo $1 | tr : .) # replace : with .
filename="$filename.json"


snyk container test --json-file-output="_scans/$filename" $image
