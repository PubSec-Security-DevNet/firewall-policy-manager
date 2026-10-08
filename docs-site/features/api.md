# API

The FastAPI contract is versioned under `/api/v1`. Read endpoints cover health, overview, delegated context, normalized inventory, provider status, synchronization evidence, audit, users, groups, grants, and ChangeSets. Scoped bearer tokens are revocable, optionally expiring, and limited by both token scope and the target User’s effective authorization.
