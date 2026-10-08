# Workers, scheduler, and recovery

Slow provider work runs through Redis-backed workers. The scheduler is a separate singleton process protected by a PostgreSQL advisory lock so duplicate schedules do not run concurrently.

Workers claim deployment work with durable leases and heartbeats. If a lease expires, the operation becomes `RECONCILIATION_REQUIRED`; the system does not assume an unknown provider call failed and blindly repeat it.

## Recovery sequence

1. Identify whether the API, PostgreSQL, Redis, worker, scheduler, or provider is unavailable.
2. Preserve logs and the correlation/provider operation identifiers.
3. Restore the failed dependency and verify readiness.
4. Inspect the durable ChangeSet or deployment state.
5. Reconcile an ambiguous provider result before retrying.
6. Confirm that schedules resume once and that device results converge.

Scheduled deployment batches active staged work by provider connection and respects connection pause windows. An authorized forced deployment uses the same planning and evidence boundaries; “force” does not bypass approval, capability, TLS, or authorization controls.
