# Public documentation site

This directory is the versioned public documentation site for Firewall Policy Manager.

## Why VitePress

VitePress produces a fully static build, keeps Markdown first-class, and provides local search and
navigation without adding documentation dependencies to the application runtime image.

## Local development

```sh
npm ci
npm run dev
npm run build
npm run preview
```

The root `Makefile` exposes `make docs-build` and `make docs-preview`. `docs-build` installs the
locked dependencies before building; `docs-preview` installs them only when needed and then serves
the exact static bundle for publication.

Run `make docs-screenshots` from the repository root to regenerate the checked-in product
screenshots from the local deterministic fixture. The application and an isolated Chrome instance
with remote debugging must already be running as described by the screenshot script's environment
variables. Review every generated image for fixture-only data before committing it.

## Publication safety

- Screenshots are captured from the local deterministic fixture and redacted at capture time for development labels and session identity.
- Do not add browser profiles, cookies, local storage, session storage, tokens, provider credentials, private URLs, or customer data.
- Describe only behavior supported by the current application and tested deployment.
- Keep private repository and AI-only planning guidance out of the public site.
