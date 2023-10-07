#!/bin/bash

set -e

required_variables=("AWS_REGION" "QUEUE_NAME")

for var in "${required_variables[@]}"; do
  if [ -z "${!var}" ]; then
    echo "$var should be set."
    exit 1
  fi
done

sed -i "s/<AWS_REGION>/$AWS_REGION/g" /etc/nginx/conf.d/default.conf

exec /usr/bin/openresty -g 'daemon off;'
