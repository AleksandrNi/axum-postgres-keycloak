#!/bin/bash

COMPOSE_FILE="docker-compose.yaml"
docker-compose -f $COMPOSE_FILE up -d --force-recreate postgres \
  && sleep 2 \
  && docker-compose -f $COMPOSE_FILE up -d keycloak
