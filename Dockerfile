ARG KEYCLOAK_VERSION=26.4.2

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS builder

COPY ./build/libs/*-all.jar /opt/keycloak/providers

ENTRYPOINT [ "/opt/keycloak/bin/kc.sh", "start-dev" ]
