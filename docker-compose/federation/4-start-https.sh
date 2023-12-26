#!/bin/bash

set -e

bb=$(tput bold)
nn=$(tput sgr0)

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

fingerprint() {
	# calculate the SHA1 digest of the DER bytes of the certificate using the
	# "coreutils" output format (`-r`) to provide uniform output from
	# `openssl sha1` on macOS and linux.
	cat $1 | openssl x509 -outform DER | openssl sha1 -r | awk '{print $1}'
}

BROKER_WEBAPP_AGENT_FINGERPRINT=$(fingerprint ${DIR}/docker/broker-webapp/conf/agent.crt.pem)
QUOTES_SERVICE_AGENT_FINGERPRINT=$(fingerprint ${DIR}/docker/stock-quotes-service/conf/agent.crt.pem)

echo "${bb}Starting https server for the broker-webapp...${nn}"
docker-compose -f "${DIR}"/docker-compose.yaml exec -T broker-webapp /usr/local/bin/https_tutorials_server &

echo "${bb}Starting https client for the stock-quotes-service...${nn}"
docker-compose -f "${DIR}"/docker-compose.yaml exec -T stock-quotes-service /usr/local/bin/https_tutorials_client -ip federation_broker-webapp_1
