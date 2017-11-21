#!/bin/bash

set -e

export DISPATCHER_PORT=7077
export DISPATCHER_UI_PORT=7076

# determine scheme and derive WEB
SCHEME=http
OTHER_SCHEME=https
if [[ "${SPARK_SSL_ENABLED}" == true ]]; then
	SCHEME=https
	OTHER_SCHEME=http
fi

export DISPATCHER_UI_WEB_PROXY_BASE="/service/${DCOS_SERVICE_NAME}"

# start service
exec runsvdir -P /etc/service

