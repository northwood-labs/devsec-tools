#!/bin/sh
if [ -z "${AWS_LAMBDA_RUNTIME_API}" ]; then
    exec /usr/local/bin/aws-lambda-rie /var/runtime/bootstrap
else
    exec /var/runtime/bootstrap
fi
