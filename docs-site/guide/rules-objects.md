# Rules & objects

The Rules and Objects workspaces are where delegated teams do policy work. Both are backed by normalized provider inventory and both enforce ownership and use rights at the API boundary.

## Rules

Delegated rules have exactly one owning Group. The workspace supports the rule lifecycle represented by the current provider capability: create, modify, delete, and reorder within the Group’s mapped provider category. The creator and last modifier are recorded separately from ownership.

Every rule element is checked independently:

- source and destination zones;
- network objects and manual networks;
- services and ports;
- applications and application filters;
- URLs and URL groups.

Reordering is constrained to the Group’s provider section. It cannot move a rule across Groups, policies, protected sections, or provider-owned boundaries.

## Objects

Objects discovered from FMC/SCC are provider-owned by default. They can be visible without being usable. An explicit `USE` grant is separate from `MODIFY` and `DELETE` authority.

Application-owned objects use the immutable Group slug:

```text
<GROUP-SLUG>__<OBJECT-NAME>
```

The current normalized creation surface covers `NETWORK`, `PORT_SERVICE`, `URL`, `APPLICATION`, and `APPLICATION_FILTER` when the provider advertises tested support. Creation, modification, and deletion also check canonical equivalence, name conflicts, dependencies, IP containment, revisions, and ownership evidence.
