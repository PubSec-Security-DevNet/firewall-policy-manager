# TLS and certificates

`./scripts/production.sh setup` creates a self-signed certificate for the public hostname when
no PEM pair exists. Clients must explicitly trust that certificate. Install a CA-issued pair
before broad user access.

After setup has created the runtime directories, install your trusted certificate and matching
unencrypted key, then reload HTTPS:

```sh
sudo install -o root -g root -m 0644 /secure/source/fullchain.pem \
  /opt/firewall-manager/runtime/tls/fullchain.pem
sudo install -o root -g root -m 0600 /secure/source/privkey.pem \
  /opt/firewall-manager/runtime/tls/privkey.pem
./scripts/production.sh cert-reload
```

The certificate SAN must cover `APP_PUBLIC_HOST`. The full chain includes required intermediates.
Coordinate replacement of both files so the proxy is not restarted with a partial pair.

For a generated self-signed pair, use `./scripts/production.sh cert-refresh`. It refuses to replace
a CA-issued certificate, and clients must trust the replacement. No image rebuild is needed.

Setup preserves existing hostname settings and certificates. If your public hostname changes,
follow [the hostname-change procedure](./production#if-the-public-hostname-changes) and update
OIDC callback URLs as well.

Provider TLS is independent from browser HTTPS. Keep FMC/SCC certificate verification enabled
and configure provider trust through the connection settings.
