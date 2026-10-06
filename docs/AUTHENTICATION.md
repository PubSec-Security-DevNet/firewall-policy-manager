# Production authentication

Firewall Manager uses a backend-for-frontend OpenID Connect Authorization Code flow. The browser
never receives provider client secrets or access/refresh tokens. A successful provider identity is
first matched by an explicitly provisioned external identity mapping using issuer + provider `sub`.
Email and display name claims are metadata only and are never used to authorize or auto-link a User;
login does not provision a User or grant application access. Groups, active Group, policy grants,
approval, and deployment authorization remain application-owned and server-side.

## Provider configuration

For new deployments, configure providers in the administrator UI. `OIDC_PROVIDERS` remains an
optional bootstrap/compatibility fallback; it should not be used for production secret storage.
Each
entry has `id`, `kind` (`entra`, `duo`, or `generic`), `display_name`, `issuer_url`, `client_id`,
`client_secret`, and optional `scopes`, claim names, and `logout`. `issuer_url` is the only
provider location supplied by an operator; discovery derives authorization, token, and JWKS
endpoints and validates the discovered issuer. Browser requests cannot select an arbitrary issuer.

Example shape (use a deployment secret reference/injection for the secret value):

```json
[{"id":"entra-main","kind":"entra","display_name":"Microsoft Entra ID","issuer_url":"https://login.microsoftonline.com/<tenant-id>/v2.0","client_id":"...","client_secret":"..."}]
```

The redirect URI is derived from `APP_PUBLIC_URL`:
`<APP_PUBLIC_URL>/api/v1/auth/<provider-id>/callback`. Register that exact HTTPS URI with the
identity provider. Entra requires an application registration in the organization tenant. Duo SSO
requires an OIDC application/integration in Duo Admin Panel. Generic OIDC uses the provider's
standard discovery document and can support other enterprise OIDC providers without a new auth
stack.

Production requires HTTPS issuer and discovered endpoints and either deployment-injected
`APP_SECRET_KEY` or the configured Vault secret provider. The application
accepts only RS256 ID tokens, validates the JWKS signature,
issuer, audience, expiry, and one-time browser nonce/state binding. Sessions are opaque,
server-side, HttpOnly, Secure in staging/production, SameSite Lax, idle/absolute bounded, and
revocable on logout. Cookie-authenticated state changes also require a double-submit CSRF token
(`fm_csrf` cookie plus `X-CSRF-Token` header). Periodically remove expired sessions as an operational
maintenance task; the scheduler now runs that cleanup automatically. Production also validates
HTTPS-only configuration, adds security response headers, and applies a bounded API request rate
limit. Interactive Swagger, ReDoc, and OpenAPI endpoints are disabled outside development and test.

## API integrations

Platform Admins can create a scoped token for an application User with
`POST /api/v1/admin/users/{user_id}/api-tokens`. The request accepts a name, `read`, `write`, or
`admin` scopes, and an optional expiry. The response contains the raw `fm_...` token once; the
application stores only its SHA-256 hash. Send it as `Authorization: Bearer <token>`.

`read` tokens may call read endpoints, `write` tokens may call state-changing endpoints, and
`admin` tokens may call administration endpoints. The token's User role, organization, current
grants, and revocation state still apply. Use `DELETE /api/v1/admin/api-tokens/{token_id}` to
revoke a token, and keep tokens short-lived and narrowly scoped.

## Operations

Provision application Users and their explicit external issuer/subject mappings before enabling login. Changes to
provider configuration require a deployment restart and should be tested against the provider's
non-production tenant. Keep `APP_SECRET_KEY` stable across API, worker, and scheduler replicas;
rotate it only with the documented ciphertext migration procedure. Never log the provider secret,
authorization code, ID token, or session cookie.

Production may set `SECRET_STORE_PROVIDER=vault` and provide `VAULT_URL`, `VAULT_SECRET_PATH`,
and an injected `VAULT_TOKEN` to resolve `APP_SECRET_KEY` from HashiCorp Vault KV v2. The token is
used only at runtime and is not stored in PostgreSQL.

Run `make secret-check` after deployment to decrypt-validate every stored secret without printing
its value. For rotation, inject `OLD_APP_SECRET_KEY`, `NEW_APP_SECRET_KEY`, and an incremented
`NEW_SECRET_STORE_KEY_VERSION` only into the one-shot `make secret-rotate` job. Verify with
`make secret-check`, then remove both key variables from the job environment. Keep the old key
available for recovery until verification and the backup window are complete.

For first production access, run `python -m firewall_manager.bootstrap_admin` inside the trusted
application environment with `BOOTSTRAP_ORGANIZATION_NAME`, `BOOTSTRAP_ADMIN_EMAIL`,
`BOOTSTRAP_ADMIN_DISPLAY_NAME`, `BOOTSTRAP_ADMIN_ISSUER`, and `BOOTSTRAP_ADMIN_SUBJECT` injected
only for that command. It refuses to run once any application User exists. Remove the variables
after success; there is no public bootstrap route, password, or default credential.

## Existing deployment recovery

If an existing organization has no OIDC providers, the login page intentionally remains in the
no-provider state. It does not expose the first-run wizard, because treating every provider-less
database as new would allow an unauthenticated visitor to claim an existing deployment.

An operator with shell access can authorize a one-time recovery window:

```sh
python -m firewall_manager.recovery_setup
```

The command automatically targets the sole organization. If the database contains more than one,
discover and select the target explicitly:

```sh
python -m firewall_manager.recovery_setup --list-organizations
python -m firewall_manager.recovery_setup --organization-name "Organization Name"
```

The command prints a short-lived URL containing a one-time recovery code. The recovery form accepts
a new administrator display name, email, OIDC issuer/subject, and provider credentials. Successful
completion creates a pending admin User keyed by the supplied email and adds the OIDC provider with
its client secret encrypted in SecretStore. On the first successful login, the provider's stable
identity is automatically bound to that email and the external identity mapping is created. The
organization and existing data are preserved. The
recovery code is stored only as a hash, expires after 30 minutes by default, and is consumed after
successful setup. Do not send the URL through an untrusted channel.

For a Docker Compose deployment, run the command in the backend container after applying the latest
migration:

```sh
docker compose exec backend alembic upgrade head
docker compose exec backend python -m firewall_manager.recovery_setup
```

If provider records must be removed before recovery, use the guarded removal command. It preserves
the organization, Users, and application data, but deletes all OIDC providers for the selected
organization, their encrypted client secrets, and their external-identity mappings:

```sh
python -m firewall_manager.remove_oidc_providers --list-organizations
python -m firewall_manager.remove_oidc_providers \
  --organization-name "Organization Name" --confirm
```

This command is destructive and requires `--confirm`. Run it only from the trusted application
environment, then use `recovery_setup` to configure a replacement provider and administrator.

## Platform Admin proxy sessions

Platform Admins may proxy as an active non-Platform-Admin User from the Users directory. A reason
is required and recorded with the proxy start event. The proxied User supplies the effective
authorization context, while the Platform Admin remains the accountable actor in audit evidence.
The application displays a persistent proxy banner and provides an explicit exit action. Proxying
is available for OIDC sessions; development authentication does not support proxy sessions.

## Development OIDC test

With `DEV_AUTH_ENABLED=true`, the administrator UI provides a **Test OIDC login** action for each
configured provider. It runs the real provider redirect, callback, token exchange, discovery, JWKS,
nonce, and state validation without changing the normal development API principal. Keep development
authentication enabled while testing; a successful OIDC callback returns to the application, while
normal API requests continue to use the configured development user. `APP_SECRET_KEY` must still be
set to a stable valid key because it protects provider secrets and the OIDC state/session cookies.
