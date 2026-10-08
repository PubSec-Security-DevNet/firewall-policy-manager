# Delegated administration

Platform teams define the lane; delegated teams operate inside it. The authorization model combines current User state, one Active Group, one Access Policy, explicit policy capabilities, and resource-level grants.

## Administrator controls

- create and disable Users and Groups with revision-aware updates;
- manage Group membership without treating membership as a grant;
- assign Access Policies and map each Group to its controlled provider rule category;
- grant directional security zones, object USE, object creation classes, and authorized IPv4/IPv6 ranges;
- separate rule create, modify, delete, and reorder rights;
- require approval and assign distinct approver, firewall-operator, and administrator roles;
- issue and revoke scoped API tokens;
- audit every privileged change.

## Delegated experience

The visible policy, rule, object, and zone inventory is filtered to the selected Group and policy. The server repeats the same checks independently, including provider-manager scope for each granted resource.

Rules have one owning Group and remain in its mapped provider category. Application-managed objects also have authoritative ownership. A User may receive USE access to a shared object while modify and delete remain unavailable. Manual network values and created network objects must remain inside authorized ranges.

<AppScreenshot src="/screenshots/access-grants.png" alt="Access grants administration showing delegated policy and resource boundaries" label="Access grants" caption="Policy capabilities, object use, zones, address ranges, creation rights, and category mappings stay explicit." />

See [Authorization and Active Group](../security/authorization) for the no-union model.
