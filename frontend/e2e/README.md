# End-to-end development tools

The Playwright spec is the ordinary browser test suite:

```bash
npm run e2e
```

The CDP scripts are optional local tools for inspecting a running development
stack in an existing Chromium session. Start the frontend first, launch
Chromium with remote debugging enabled, and set `E2E_CDP_ENDPOINT` when it is
not `http://127.0.0.1:9222`.

Available tools include:

- `npm run e2e:cdp:routes` — route and accessibility smoke checks
- `npm run e2e:cdp:app` — authenticated application screen sweep
- `npm run e2e:cdp:functions` — interactive function checks
- `npm run e2e:cdp:faults` — unauthenticated and API-fault checks
- `npm run e2e:cdp:fixture` — create repeatable approval-flow test data
- `npm run e2e:cdp:coverage` — run the CDP checks and write a JSON summary

These tools use deterministic development fixtures and must not be pointed at
production. Screenshot and report locations can be changed with the
`E2E_*_DIR` variables used by the individual tools.
