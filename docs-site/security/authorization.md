# Authorization and Active Group

The decisive context for delegated work is:

```text
Authenticated User + Active Group + Access Policy + explicit grants
```

Membership only makes a Group selectable. It does not grant a policy, object, zone, network range, approval, or deployment right.

## Why permissions do not union

Alice belongs to both Finance and Engineering. When she selects **Finance** as her Active Group, the authorization service considers only Finance:

| Applies now | Explicitly does not apply |
| --- | --- |
| Finance policy assignments | Engineering policy assignments |
| Finance capabilities | Engineering capabilities |
| Finance object and zone grants | Engineering object and zone grants |
| Finance authorized IPv4/IPv6 ranges | Engineering network ranges |
| Finance category mapping | Engineering rule section |

Switching the selector establishes a different server-validated context. It is never just a table filter, and it cannot transfer an existing ChangeSet into another Group.

## Separate rights for separate risks

Policy rights distinguish viewing, rule creation, rule modification, deletion, ordering, object modification, object deletion, submission, approval, and deployment. Administrators can let a team assemble a valid rule without also letting it approve or deploy that rule.

### Use versus modify

A Finance rule may need to reference a shared DNS object. An **object USE grant** allows that reference. It does not allow Finance to rename the object, change its value, or delete it.

Application-managed objects have an authoritative owning Group and policy context. Provider-only resources remain unmanaged until an explicit reconciliation decision; familiar names do not establish ownership. Network object creation and modification also check normalized IPv4 or IPv6 values against the Group's authorized ranges.

## Defense through execution

Authorization is checked when data is listed, when an operation is drafted, during preflight, and again before a provider worker executes. Disabled Users, revoked membership, changed grants, stale revisions, and new drift can therefore stop work that was valid earlier.
