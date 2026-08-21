# MeshChat Relay — Docker

This directory contains the Docker configuration for running a MeshChat relay.

## Requirements

- Docker
- Docker Compose
- A public hostname with TLS termination
- A reverse proxy such as nginx

## Configuration

Copy `compose.yaml` and adjust:

- `RELAY_WSS_URL` — public WebSocket URL of the relay
- `TRUSTED_PROXIES` — reverse-proxy address(es), if applicable
- buffer limits as required

The example configuration binds the HTTP and WebSocket ports to
`127.0.0.1`, expecting a reverse proxy to provide public HTTPS/WSS access.

## Start

From this directory:

```bash
docker compose up -d --build