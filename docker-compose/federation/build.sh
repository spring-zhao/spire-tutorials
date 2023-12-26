#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

(cd "${DIR}"/src/broker-webapp && CGO_ENABLED=0 GOOS=linux go build -v -o "${DIR}"/docker/broker-webapp/broker-webapp)
(cd "${DIR}"/src/stock-quotes-service && CGO_ENABLED=0 GOOS=linux go build -v -o "${DIR}"/docker/stock-quotes-service/stock-quotes-service)

(cd "${DIR}"/src/https_tutorials/server && CGO_ENABLED=0 GOOS=linux go build -v -o "${DIR}"/docker/broker-webapp/https_tutorials_server)
(cd "${DIR}"/src/https_tutorials/client && CGO_ENABLED=0 GOOS=linux go build -v -o "${DIR}"/docker/stock-quotes-service/https_tutorials_client)

docker-compose -f "${DIR}"/docker-compose.yaml build
