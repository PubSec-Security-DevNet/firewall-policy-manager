# Production monitoring

The canonical single-host deployment includes Prometheus and Grafana behind the optional
`monitoring` Compose profile:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml --profile monitoring up -d prometheus grafana
```

Prometheus is container-private. Grafana binds to host loopback only, requires the generated admin
password file, disables anonymous access and sign-up, and should be reached through an SSH tunnel
or approved authenticated ingress.

The API exposes Prometheus text metrics at `/api/v1/metrics`. Caddy returns 404 for this path, so it
is available only to Prometheus on the internal monitoring network. The endpoint reports HTTP
request totals plus worker and scheduler heartbeat gauges backed by Redis. Scrape every 15–30
seconds and aggregate across API replicas in an advanced multi-replica deployment.

Included alerts cover:

- API scrape availability;
- HTTP 5xx rates;
- sustained HTTP 429 rate limiting;
- stale worker heartbeat;
- stale scheduler heartbeat.

The included dashboard shows request status/rate limiting and worker/scheduler health. Extend the
monitoring platform with database, Redis, host, and container exporters when queue depth, storage,
and database saturation are required. Alert operationally on overdue backups, provider sync,
long-running deployments, and reconciliation state using the organization's event pipeline.

Correlate alerts with response `X-Correlation-ID` values and durable audit/deployment records.
Never put credentials, tokens, provider payloads, cookies, or high-cardinality resource IDs in
metric labels.

The request counters are process-local. A multi-replica deployment must scrape every API replica
and enforce ingress-level rate limits so a process restart cannot reset the global limit.
