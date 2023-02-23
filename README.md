# Axum Rest Service

## Project information

* Multi-module project
* Postgres
* Migrations
* Sqlx
* Keycloak: clients implemented ["bearer-only", "confidential"]
* JWT
* Custom errors - AppGenericError
* Docker-compose

## Features

This project is aimed at showcasing how you could do:

* Project's layer structure - Controller, Service, Repository
* Using Keycloak as user, permission, roles managing service
* Using Postgres connection pool
* Using Redis connection pool

## Additionally added 
* Keycloak realm:       /distribution/dev/keycloak/imports
* Postman collection:   /distribution/dev/postman

## Entrypoint
 ```
  ./src/bin/servers.rs main 
 ```

## Run
 - docker containers
 ```
 $ cd distrbution/dev
 $ docker-compose up -d
 ```
- build and start app
 ```
 $ cargo build --release
 $ ./target/release/server
 ```
- for development
 ```
 $ cargo watch -x run
 ```