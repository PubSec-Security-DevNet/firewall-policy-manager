# Cisco Security Cloud Control

The SCC adapter uses an API-only token and a controlled region selection. It presents the same governed product workflow as FMC while preserving SCC-specific authentication, resource, and deployment behavior behind the provider boundary.

## Supported product workflow

- discover tenant inventory, policies, devices, rules, objects, zones, and provider versions;
- synchronize complete paginated inventory and preserve failure evidence for incomplete reads;
- execute supported rule, ordering, category, network, port-service, and URL changes from approved ChangeSets;
- inspect pending provider configuration, schedule deployment, and monitor provider tasks;
- retain per-device deployment outcomes and fence ambiguous results for reconciliation;
- surface drift, missing resources, provider-only resources, and revision conflict.

## Onboarding safely

Create a dedicated SCC token with the minimum required access, select the correct supported region, add the connection with writes disabled, test the complete read path, then synchronize. Capability evidence remains tied to the connection's observed provider version. Enable writes only after approved non-production mutation and deployment validation.

## Deployment boundary

See the [provider-specific deployment contract](../installation/deployment-safety.md). Deployment
uses current assignments, expanded pending evidence, recorded mutation results and durable intent.
The provider does not document atomic exclusion of direct edits after final preflight. Strict
exclusivity requires an operational change window.

New deployments map SCC device UIDs to cdFMC IDs and use the cdFMC selective deployment and task APIs.
