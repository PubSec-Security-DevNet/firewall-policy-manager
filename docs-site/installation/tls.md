# TLS and certificates

Public HTTPS is the production ingress boundary. Install a trusted `fullchain.pem` and matching unencrypted `privkey.pem` under the protected runtime TLS directory before setup. The certificate SAN must contain `APP_PUBLIC_HOST` exactly.

```sh
sudo install -o root -g root -m 0644 /secure/source/fullchain.pem \
  /opt/firewall-manager/runtime/tls/fullchain.pem
sudo install -o root -g root -m 0600 /secure/source/privkey.pem \
  /opt/firewall-manager/runtime/tls/privkey.pem
./scripts/production.sh cert-reload
```

If both PEM files are absent, the production stack can generate a hostname-correct self-signed pair. This provides encryption for installation and controlled environments, but clients must explicitly trust the new certificate. A partial pair fails closed.

`cert-refresh` replaces only a self-signed pair and refuses to overwrite a CA-issued certificate. Installing a renewed trusted pair should be atomic, followed by `cert-reload` and an HTTPS readiness check.

Provider TLS is independent from public ingress TLS. FMC/SCC trust remains verified through system trust or configured private CA material, with hostname verification required. Never disable certificate verification to resolve a connection problem.
