# Policies & working context

The Policies workspace is the first decision point for delegated work. It is where an operator chooses the provider manager, policy, Active Group, and Access Policy that define what the rest of the application can show and change.

## Why the context matters

The application evaluates:

```text
Authenticated User + Active Group + Access Policy → effective permissions
```

Changing the Group re-evaluates policies, rules, objects, zones, IP ranges, ordering boundaries, and capabilities. A user who belongs to Finance and Engineering does not receive the union of both Groups’ grants.

## Policy mapping

Each Group/policy pair maps to a provider rule category. The mapping is application-authoritative: a provider category with a similar name does not establish ownership, and a delegated rule cannot cross the Group’s category boundary without an explicit administrative capability.

## Operator workflow

1. Open Policies and select the manager and policy.
2. Select the Group whose work you are performing.
3. Review the effective capabilities and available inventory.
4. Move to Rules or Objects; the server carries the same context into every request.
5. Create a ChangeSet before submitting a mutation.

If no policy is delegated to the selected Group, the correct result is an empty/blocked workspace—not an implicit fallback to another membership.
