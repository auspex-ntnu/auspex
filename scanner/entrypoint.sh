#!/usr/bin/env bash

# This script reads secrets files and sets environment variables

# Example: 
#
# SNYK_TOKEN_FILE=/run/secrets/snyk_token
# Automatically becomes:
# SNYK_TOKEN=`cat $SNYK_TOKEN_FILE`

set -e

file_env() {
   local var="$1"
   local fileVar="${var}_FILE"
   local def="${2:-}"

   if [ "${!var:-}" ] && [ "${!fileVar:-}" ]; then
      echo >&2 "error: both $var and $fileVar are set (but are exclusive)"
      exit 1
   fi
   local val="$def"
   if [ "${!var:-}" ]; then
      val="${!var}"
   elif [ "${!fileVar:-}" ]; then
      val="$(< "${!fileVar}")"
   fi
   export "$var"="$val"
   unset "$fileVar"
}

file_env "SNYK_TOKEN"

uvicorn scanner:app --host 0.0.0.0 --port 80