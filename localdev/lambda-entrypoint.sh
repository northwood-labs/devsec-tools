#!/bin/sh

##
# Start the Runtime Interface Emulator (RIE), then the Delve debugger, then our
# Lambda function -- all in a chain.
##

echo "------------------"
/dlv version
echo "------------------"

if [ -z "${AWS_LAMBDA_RUNTIME_API}" ]; then
    exec /usr/local/bin/aws-lambda-rie /var/runtime/bootstrap
else
    exec /var/runtime/bootstrap
fi

echo "RIE running as PID ${PID}."
echo "------------------"

# /dlv --listen=:42424 --headless=true --api-version=2 --accept-multiclient exec
# dnf -y install htop
