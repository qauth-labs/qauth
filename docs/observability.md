# Observability Guide

This guide has moved to the documentation site: [Observability Guide](https://docs.qauth.dev/operate/observability/).

In short: `GET /health` is liveness and `GET /ready` runs the readiness checks
of the process's service roles, both on the public port and on any host
([Health and readiness](https://docs.qauth.dev/operate/observability/#health-and-readiness)).
The Prometheus metrics are served at `GET /internal/metrics` on the internal
listener, never on the public port
([Who can read the metrics](https://docs.qauth.dev/operate/observability/#who-can-read-the-metrics)).
