# Production monitoring

The API exposes Prometheus text metrics at `/api/v1/metrics`. Keep this endpoint on the internal
monitoring network; it is intentionally not part of the authenticated browser API. The endpoint
currently reports HTTP request totals and process-local worker job counters. Scrape every 15–30
seconds and aggregate across API replicas.

Minimum alerts:

- API readiness fails for two consecutive checks;
- worker health fails because the Redis heartbeat is older than two minutes;
- scheduler health or queue depth is stale for two intervals;
- HTTP 5xx or 429 rates exceed the deployment baseline;
- provider connection has no successful sync within its configured interval plus grace period;
- deployment remains `DEPLOYING` beyond the provider's expected window;
- deployment becomes `RECONCILIATION_REQUIRED` or `UNKNOWN`;
- secret-store validation or provider credential retrieval fails;
- PostgreSQL backup and restore checks are overdue.

Dashboards should include request rate/latency/status, queue depth and age, worker/scheduler
heartbeats, provider sync duration/status, deployment state and age, reconciliation backlog, and
database connection saturation. Correlate alerts with the response `X-Correlation-ID` and the
durable audit/deployment record; never put credentials, tokens, provider payloads, or cookies in
metric labels.

The current in-process request counters are useful for local and single-process deployments. A
multi-replica production deployment must also scrape every replica and enforce ingress-level
rate limits so an individual process restart cannot reset the global limit.
