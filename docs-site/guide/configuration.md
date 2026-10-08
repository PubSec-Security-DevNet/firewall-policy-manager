# Configuration

The production helper creates `/opt/firewall-manager/runtime/.env.production` from the repository’s safe example and stores secret values in separate protected files. `.env.example` is for local development only.

| Area | Settings | Guidance |
| --- | --- | --- |
| Environment | `APP_ENVIRONMENT`, `APP_PUBLIC_URL` | Use staging/production and an HTTPS public URL. |
| Database | `POSTGRES_DB`, `POSTGRES_USER` | Password material is mounted from the protected `postgres_password` file. |
| Queue | Redis settings | The canonical private Redis service reads its password from a protected file. |
| Secrets | `APP_SECRET_KEY_FILE`, `SECRET_STORE_KEY_VERSION` | Keep the file-mounted application key stable and escrow it separately from database backups. |
| Authentication | Browser administrator UI | Configure and test Entra, Duo SSO, or generic OIDC providers during first-time setup. |
| Sessions | `AUTH_SESSION_IDLE_MINUTES`, `AUTH_SESSION_ABSOLUTE_HOURS` | Bound and revoke sessions operationally. |
| Audit | `AUDIT_RETENTION_MONTHS` | Set retention to match the organization’s policy. |

Never put provider credentials, OIDC client secrets, Docker secret contents, or the application root key in an image, repository, screenshot, shell transcript, or issue.
