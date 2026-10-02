# Ingress security requirements

The application enforces HTTPS configuration, secure cookies in staging/production, security
headers, and a per-process API limit. A multi-replica deployment must add the global controls at
the ingress/load-balancer layer.

Required ingress behavior:

- terminate only trusted TLS certificates and redirect HTTP to HTTPS;
- preserve `X-Correlation-ID` or generate one at the edge;
- apply an authenticated API rate limit per client/token and a stricter login/callback limit;
- allow only the configured frontend origin for credentialed CORS;
- expose `/api/v1/metrics` only to the monitoring network;
- expose PostgreSQL, Redis, worker, and scheduler ports only on private networks;
- do not log `Authorization`, cookies, OIDC codes, or request bodies containing secrets.

Example Nginx shape (adapt limits and addresses to the deployment):

```nginx
limit_req_zone $binary_remote_addr zone=fm_api:10m rate=10r/s;
location /api/ {
    limit_req zone=fm_api burst=30 nodelay;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Correlation-ID $http_x_correlation_id;
    proxy_pass http://firewall_manager_api;
}
location = /api/v1/metrics { allow 10.0.0.0/8; deny all; proxy_pass http://firewall_manager_api; }
```
