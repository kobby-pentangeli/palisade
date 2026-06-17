# Deployment Guide

This guide covers running Palisade in production: the demo compose stack, a container image, and a hardened `systemd` unit. For the security posture and what the proxy does and does not defend against, see [SECURITY.md](../SECURITY.md); for the full configuration reference, see the [README](../README.md#configuration).

All deployments share one input: a single TOML configuration file. Start from [`config.example.toml`](../config.example.toml) and edit it for your backends. Only `listen` and at least one `[[upstreams]]` entry are required.

## Demo stack (Docker Compose)

The fastest way to see Palisade proxy real traffic. The stack runs the proxy in front of a throwaway echo backend:

```bash
docker compose up --build
```

Then, from another shell:

```bash
# Proxied request: the echo backend reports the headers Palisade injected
# (X-Forwarded-For, X-Forwarded-Proto, the rewritten Host) and that it was reached.
curl -i http://localhost:8100/

# Operational endpoints, published to the host loopback only.
curl -s http://127.0.0.1:9100/livez
curl -s http://127.0.0.1:9100/readyz
curl -s http://127.0.0.1:9100/metrics
```

The proxy config used by the stack is [`config.docker.toml`](./config.docker.toml); the compose file is at the repository root.

## Container image

The [`Dockerfile`](../Dockerfile) is a two-stage build producing a small image: the binary is compiled on `rust:1.85` and copied into `gcr.io/distroless/cc-debian12:nonroot`, which carries no shell or package manager and runs as an unprivileged user.

```bash
docker build -t palisade:0.2.0 .

docker run --rm \
  -p 8100:8100 \
  -v "$PWD/config.toml:/etc/palisade/config.toml:ro" \
  palisade:0.2.0
```

The image reads its config from `/etc/palisade/config.toml` (mount yours there) and logs JSON by default. Bind `listen` to `0.0.0.0` inside the container so the proxy is reachable through the published port. The container stops cleanly on `SIGTERM`, draining in-flight connections within `shutdown_timeout`.

## systemd

For a bare-metal or VM host, [`palisade.service`](./palisade.service) is a hardened unit (dynamic unprivileged user, `ProtectSystem=strict`, a `@system-service` syscall filter, `MemoryDenyWriteExecute`, and a read-only config path):

```bash
install -Dm0755 target/release/palisade /usr/local/bin/palisade
install -Dm0644 deploy/palisade.service /etc/systemd/system/palisade.service
install -Dm0640 config.example.toml      /etc/palisade/config.toml   # then edit

systemctl daemon-reload
systemctl enable --now palisade
journalctl -u palisade -f
```

Binding a privileged port (e.g. `443` for TLS termination) requires granting `CAP_NET_BIND_SERVICE`; the unit documents how. The default `8100` needs no capabilities.

## Operational notes

- **Health gating.** Point your load balancer or orchestrator readiness probe at `GET /readyz` on the admin listener: it returns `200` while at least one upstream is healthy and `503` otherwise. Use `GET /livez` for the liveness/restart probe.
- **Metrics.** Scrape `GET /metrics` (OpenMetrics) from the admin listener. Keep the admin bind address on an internal interface or host loopback; it must differ from the data-plane `listen` and should never be world-reachable.
- **TLS.** For TLS termination, set the `[tls]` section to your PEM certificate and key paths and mount them read-only. Upstream TLS origination needs no configuration beyond an `https://` upstream address.
- **Graceful shutdown.** The proxy drains on `SIGINT`/`SIGTERM`; give it at least `shutdown_timeout` seconds to stop (the systemd unit sets `TimeoutStopSec=35s`).
