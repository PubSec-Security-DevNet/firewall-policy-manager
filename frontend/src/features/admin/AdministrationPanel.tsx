import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  IconBuildingCommunity,
  IconEdit,
  IconKey,
  IconLink,
  IconPlus,
  IconShieldCheck,
  IconShieldLock,
  IconUserCheck,
  IconUserPlus,
  IconUsers,
} from '@tabler/icons-react';

import {
  ApiError,
  createAdministrativeResource,
  developmentIdentitiesChangedEvent,
  startProxySession,
  loadAdministration,
  revokeAuthorizationResource,
  updateAdministrativeEnabled,
  updateGroupApproval,
  updateAdministrativeUserRole,
  upsertAuthorizationResource,
  type AdministrationSnapshot,
} from '../../api/client';
import {
  AppAlert as Alert,
  AppActionButton as ActionButton,
  AppButton as Button,
  AppCard as Card,
  AppCheckbox as Checkbox,
  AppDataTable,
  AppDialog as Dialog,
  AppEmptyState,
  AppErrorState,
  AppGroup as Group,
  AppLoadingState,
  AppMultiSelect as MultiSelect,
  AppSection,
  AppSelect as Select,
  AppSimpleGrid as SimpleGrid,
  AppStack as Stack,
  AppStatusBadge,
  AppTable as Table,
  AppText as Text,
  AppTextInput as TextInput,
  AppThemeIcon as ThemeIcon,
  MetricCard,
} from '../../ui';
import { Tabs } from '../../ui/tabs';
import { authorizationExpectedRevision, providerResourcesForPolicy } from './authorizationRevision';
import { AdaptivePagination, useAdaptivePageSize } from '../shared/AdaptivePagination';

type AdministrationView = 'users' | 'groups' | 'grants';
type Row = Record<string, unknown>;
type GrantEditor = { kind: string; row?: Row; objectTypes?: string[] };
type State =
  | { status: 'loading' }
  | { status: 'ready'; snapshot: AdministrationSnapshot }
  | { status: 'error'; message: string; correlationId?: string };

export function AdministrationPanel({ view }: { view: AdministrationView }) {
  const [state, setState] = useState<State>({ status: 'loading' });
  const refresh = useCallback(
    () =>
      loadAdministration()
        .then((snapshot) => setState({ status: 'ready', snapshot }))
        .catch((error: unknown) => setState(toError(error))),
    [],
  );

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const revoke = useCallback(
    (resource: string, row: Row) => {
      const label = resource === 'memberships' ? 'membership' : 'grant';
      if (!window.confirm(`Revoke this ${label}? The change takes effect immediately.`)) return;
      void revokeAuthorizationResource(resource, String(row.id), Number(row.revision))
        .then(refresh)
        .catch((error: unknown) => setState(toError(error)));
    },
    [refresh],
  );

  const toggleEnabled = useCallback(
    (resource: 'users' | 'groups', row: Row) => {
      const enabled = Boolean(row.enabled);
      const subject = resource === 'users' ? 'user' : 'group';
      if (!window.confirm(`${enabled ? 'Disable' : 'Enable'} this ${subject}?`)) return;
      void updateAdministrativeEnabled(resource, String(row.id), !enabled, Number(row.revision))
        .then(refresh)
        .then(() => {
          if (resource === 'users')
            window.dispatchEvent(new Event(developmentIdentitiesChangedEvent));
        })
        .catch((error: unknown) => setState(toError(error)));
    },
    [refresh],
  );

  if (state.status === 'loading') return <AppLoadingState label={`Loading ${view}`} />;
  if (state.status === 'error') {
    return <AppErrorState message={state.message} reference={state.correlationId} />;
  }

  const labels = resourceLabels(state.snapshot);
  if (view === 'groups') {
    return (
      <GroupsPage
        snapshot={state.snapshot}
        labels={labels}
        onSaved={refresh}
        onToggle={(row) => toggleEnabled('groups', row)}
        onApprovalToggle={(row) => {
          const required = !row.approval_required;
          void updateGroupApproval(String(row.id), required, Number(row.revision))
            .then(refresh)
            .catch((error: unknown) => setState(toError(error)));
        }}
      />
    );
  }
  if (view === 'users') {
    return (
      <UsersPage
        snapshot={state.snapshot}
        labels={labels}
        onSaved={refresh}
        onToggle={(row) => toggleEnabled('users', row)}
      />
    );
  }
  return (
    <AccessGrantsPage
      snapshot={state.snapshot}
      labels={labels}
      onSaved={refresh}
      onRevoke={revoke}
    />
  );
}

function GroupsPage({
  snapshot,
  labels,
  onSaved,
  onToggle,
  onApprovalToggle,
}: {
  snapshot: AdministrationSnapshot;
  labels: Record<string, string>;
  onSaved: () => Promise<void>;
  onToggle: (row: Row) => void;
  onApprovalToggle: (row: Row) => void;
}) {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'enabled' | 'disabled' | 'all'>('enabled');
  const [approvalFilter, setApprovalFilter] = useState<'all' | 'required' | 'not_required'>('all');
  const [createOpened, setCreateOpened] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState<Row | null>(null);
  const active = snapshot.groups.filter((row) => Boolean(row.enabled)).length;
  const groupRows: Row[] = snapshot.groups.map((group) => ({
    ...group,
    member_names: snapshot.memberships
      .filter((membership) => String(membership.group_id) === String(group.id))
      .map((membership) => labels[String(membership.user_id)] ?? 'Unknown user'),
    member_count: snapshot.memberships.filter(
      (membership) => String(membership.group_id) === String(group.id),
    ).length,
  }));
  const statusFiltered = groupRows.filter((row) =>
    statusFilter === 'all' ? true : Boolean(row.enabled) === (statusFilter === 'enabled'),
  );
  const approvalFiltered = statusFiltered.filter((row) =>
    approvalFilter === 'all'
      ? true
      : Boolean(row.approval_required) === (approvalFilter === 'required'),
  );
  const filtered = filterRows(approvalFiltered, query, ['name', 'provider_slug', 'member_names']);
  const delegatedGroups = new Set(snapshot.policy_delegations.map((row) => String(row.group_id)));
  return (
    <Stack gap="lg">
      <SimpleGrid cols={{ base: 1, sm: 3 }}>
        <MetricCard
          label="Groups"
          value={snapshot.groups.length}
          detail={`${active} enabled`}
          icon={<IconBuildingCommunity size={19} />}
        />
        <MetricCard
          label="Memberships"
          value={snapshot.memberships.length}
          detail="Across all groups"
          icon={<IconUsers size={19} />}
        />
        <MetricCard
          label="Groups with policy grants"
          value={delegatedGroups.size}
          detail="With policy access"
          icon={<IconShieldLock size={19} />}
        />
      </SimpleGrid>
      <Card>
        <AppSection
          title="Group directory"
          description="Select a Group to review and change its User membership."
          actions={
            <Group gap="sm">
              <AppStatusBadge
                value="COUNT"
                label={
                  query || statusFilter !== 'all' || approvalFilter !== 'all'
                    ? `${filtered.length} of ${groupRows.length}`
                    : `${groupRows.length} groups`
                }
              />
              <Button leftSection={<IconPlus size={16} />} onClick={() => setCreateOpened(true)}>
                Create Group
              </Button>
            </Group>
          }
        >
          <div className="fm-list-toolbar fm-list-toolbar-directory">
            <TextInput
              aria-label="Search groups"
              placeholder="Search groups"
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
            />
            <Select
              aria-label="Filter groups by status"
              value={statusFilter}
              onChange={(value) => setStatusFilter((value as typeof statusFilter) ?? 'enabled')}
              allowDeselect={false}
              data={[
                { value: 'enabled', label: 'Enabled' },
                { value: 'disabled', label: 'Disabled' },
                { value: 'all', label: 'All status' },
              ]}
            />
            <Select
              aria-label="Filter groups by approval"
              value={approvalFilter}
              onChange={(value) => setApprovalFilter((value as typeof approvalFilter) ?? 'all')}
              allowDeselect={false}
              data={[
                { value: 'all', label: 'All approval states' },
                { value: 'required', label: 'Approval required' },
                { value: 'not_required', label: 'Approval not required' },
              ]}
            />
          </div>
          <AdminTable
            label="Group directory"
            rows={filtered}
            fields={['name', 'provider_slug', 'member_count', 'approval_required', 'enabled']}
            labels={labels}
            tone="groups"
            actions={(row) => (
              <Group className="fm-group-row-actions" gap="xs" wrap="nowrap">
                <ActionButton
                  intent={row.approval_required ? 'quiet-success' : 'secondary'}
                  leftSection={<IconShieldCheck size={14} />}
                  aria-label={row.approval_required ? 'Allow direct execution' : 'Require approval'}
                  title={row.approval_required ? 'Allow direct execution' : 'Require approval'}
                  onClick={() => onApprovalToggle(row)}
                >
                  Approval
                </ActionButton>
                <ActionButton
                  intent="secondary"
                  leftSection={<IconUserPlus size={14} />}
                  aria-label="Manage members"
                  title="Manage members"
                  onClick={() => setSelectedGroup(row)}
                >
                  Members
                </ActionButton>
                <ActionButton
                  intent={row.enabled ? 'quiet-danger' : 'quiet-success'}
                  aria-label={row.enabled ? 'Disable group' : 'Enable group'}
                  title={row.enabled ? 'Disable group' : 'Enable group'}
                  onClick={() => onToggle(row)}
                >
                  {row.enabled ? 'Disable' : 'Enable'}
                </ActionButton>
              </Group>
            )}
          />
        </AppSection>
      </Card>
      <Dialog
        opened={createOpened}
        onClose={() => setCreateOpened(false)}
        title="Create Group"
        closeButtonProps={{ 'aria-label': 'Close' }}
        classNames={{
          content: 'fm-management-modal',
          header: 'fm-management-modal-header',
          body: 'fm-management-modal-body',
        }}
        centered
      >
        <CreateIdentityForm
          resource="groups"
          onSaved={onSaved}
          onCompleted={() => setCreateOpened(false)}
        />
      </Dialog>
      <MembershipManager
        mode="group"
        subject={selectedGroup}
        snapshot={snapshot}
        onSaved={onSaved}
        onClose={() => setSelectedGroup(null)}
      />
    </Stack>
  );
}

function UsersPage({
  snapshot,
  labels,
  onSaved,
  onToggle,
}: {
  snapshot: AdministrationSnapshot;
  labels: Record<string, string>;
  onSaved: () => Promise<void>;
  onToggle: (row: Row) => void;
}) {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'enabled' | 'disabled' | 'all'>('enabled');
  const [roleFilter, setRoleFilter] = useState('all');
  const [page, setPage] = useState(1);
  const pageSize = useAdaptivePageSize();
  const [createOpened, setCreateOpened] = useState(false);
  const [selectedUser, setSelectedUser] = useState<Row | null>(null);
  const [roleUser, setRoleUser] = useState<Row | null>(null);
  const [proxyUser, setProxyUser] = useState<Row | null>(null);
  const [proxyReason, setProxyReason] = useState('');
  const [proxySaving, setProxySaving] = useState(false);
  const [proxyFeedback, setProxyFeedback] = useState<Feedback | null>(null);
  const active = snapshot.users.filter((row) => Boolean(row.enabled)).length;
  const userRows: Row[] = snapshot.users.map((user) => ({
    ...user,
    group_names: snapshot.memberships
      .filter((membership) => String(membership.user_id) === String(user.id))
      .map((membership) => labels[String(membership.group_id)] ?? 'Unknown Group'),
    group_count: snapshot.memberships.filter(
      (membership) => String(membership.user_id) === String(user.id),
    ).length,
  }));
  const statusFiltered = userRows.filter((row) =>
    statusFilter === 'all' ? true : Boolean(row.enabled) === (statusFilter === 'enabled'),
  );
  const roleFiltered = statusFiltered.filter(
    (row) => roleFilter === 'all' || String(row.role) === roleFilter,
  );
  const filtered = filterRows(roleFiltered, query, [
    'display_name',
    'email',
    'role',
    'group_names',
  ]);
  const pagedUsers = filtered.slice((page - 1) * pageSize, page * pageSize);
  useEffect(() => {
    setPage(1);
  }, [query, statusFilter, roleFilter]);
  useEffect(() => {
    const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
    setPage((current) => Math.min(current, pageCount));
  }, [filtered.length, pageSize]);
  const usersWithGroups = new Set(snapshot.memberships.map((row) => String(row.user_id))).size;
  const closeProxyDialog = () => {
    if (proxySaving) return;
    setProxyUser(null);
    setProxyReason('');
    setProxyFeedback(null);
  };
  const proxyAsUser = (row: Row) => {
    setProxyUser(row);
    setProxyReason('');
    setProxyFeedback(null);
  };
  const submitProxy = async () => {
    if (!proxyUser || !proxyReason.trim()) return;
    setProxySaving(true);
    setProxyFeedback(null);
    try {
      await startProxySession(String(proxyUser.id), proxyReason.trim());
      window.location.reload();
    } catch (error) {
      setProxyFeedback({ kind: 'error', message: errorMessage(error) });
    } finally {
      setProxySaving(false);
    }
  };
  return (
    <Stack gap="lg">
      <SimpleGrid cols={{ base: 1, sm: 3 }}>
        <MetricCard
          label="Users"
          value={snapshot.users.length}
          detail={`${active} enabled`}
          icon={<IconUsers size={19} />}
        />
        <MetricCard
          label="Group members"
          value={usersWithGroups}
          detail="Users assigned to a group"
          icon={<IconUserCheck size={19} />}
        />
        <MetricCard
          label="Memberships"
          value={snapshot.memberships.length}
          detail="Active access relationships"
          icon={<IconLink size={19} />}
        />
      </SimpleGrid>
      <Card>
        <AppSection
          title="User directory"
          description="Select a User to inspect and manage their current Group assignments."
          actions={
            <Group gap="sm">
              <AppStatusBadge
                value="COUNT"
                label={
                  query || statusFilter !== 'all' || roleFilter !== 'all'
                    ? `${filtered.length} of ${roleFiltered.length}`
                    : `${userRows.length} users`
                }
              />
              <Button leftSection={<IconPlus size={16} />} onClick={() => setCreateOpened(true)}>
                Create User
              </Button>
            </Group>
          }
        >
          <div className="fm-list-toolbar fm-list-toolbar-directory">
            <TextInput
              aria-label="Search users"
              placeholder="Search users"
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
            />
            <Select
              aria-label="Filter users by status"
              value={statusFilter}
              onChange={(value) => {
                if (value === 'enabled' || value === 'disabled' || value === 'all') {
                  setStatusFilter(value);
                }
              }}
              allowDeselect={false}
              data={[
                { value: 'enabled', label: 'Enabled users' },
                { value: 'all', label: 'All users' },
                { value: 'disabled', label: 'Disabled users' },
              ]}
            />
            <Select
              aria-label="Filter users by role"
              value={roleFilter}
              onChange={(value) => setRoleFilter(value ?? 'all')}
              allowDeselect={false}
              data={[
                { value: 'all', label: 'All roles' },
                ...roleOptions.map((option) => ({
                  value: option.value,
                  label: option.label,
                })),
              ]}
            />
          </div>
          <AdminTable
            label="User directory"
            rows={pagedUsers}
            fields={['display_name', 'email', 'role', 'group_count', 'enabled']}
            labels={labels}
            tone="users"
            actions={(row) => (
              <Group gap="xs" wrap="nowrap">
                <ActionButton
                  intent="secondary"
                  leftSection={<IconUserCheck size={14} />}
                  aria-label="Proxy as user"
                  title="Proxy as user"
                  onClick={() => {
                    void proxyAsUser(row);
                  }}
                  disabled={row.role === 'admin' || !row.enabled}
                >
                  Proxy
                </ActionButton>
                <ActionButton
                  intent="secondary"
                  leftSection={<IconBuildingCommunity size={14} />}
                  aria-label="Manage groups"
                  title="Manage groups"
                  onClick={() => setSelectedUser(row)}
                >
                  Groups
                </ActionButton>
                <ActionButton
                  intent="secondary"
                  leftSection={<IconEdit size={14} />}
                  aria-label="Change role"
                  title="Change role"
                  onClick={() => setRoleUser(row)}
                >
                  Role
                </ActionButton>
                <ActionButton
                  intent={row.enabled ? 'quiet-danger' : 'quiet-success'}
                  onClick={() => onToggle(row)}
                >
                  {row.enabled ? 'Disable' : 'Enable'}
                </ActionButton>
              </Group>
            )}
          />
          <AdaptivePagination
            page={page}
            pageSize={pageSize}
            total={filtered.length}
            onPageChange={setPage}
          />
        </AppSection>
      </Card>
      <Dialog
        opened={createOpened}
        onClose={() => setCreateOpened(false)}
        title="Create User"
        closeButtonProps={{ 'aria-label': 'Close' }}
        classNames={{
          content: 'fm-management-modal',
          header: 'fm-management-modal-header',
          body: 'fm-management-modal-body',
        }}
        centered
      >
        <CreateIdentityForm
          resource="users"
          onSaved={onSaved}
          onCompleted={() => setCreateOpened(false)}
        />
      </Dialog>
      <MembershipManager
        mode="user"
        subject={selectedUser}
        snapshot={snapshot}
        onSaved={onSaved}
        onClose={() => setSelectedUser(null)}
      />
      <RoleManager
        key={roleUser ? String(roleUser.id) : 'closed'}
        user={roleUser}
        onSaved={onSaved}
        onClose={() => setRoleUser(null)}
      />
      <Dialog
        opened={proxyUser !== null}
        onClose={closeProxyDialog}
        title="Proxy as user"
        closeButtonProps={{ 'aria-label': 'Close' }}
        classNames={{
          content: 'fm-management-modal',
          header: 'fm-management-modal-header',
          body: 'fm-management-modal-body',
        }}
        centered
      >
        <form
          onSubmit={(event: React.FormEvent<HTMLFormElement>) => {
            event.preventDefault();
            void submitProxy();
          }}
        >
          <Stack gap="md">
            <div className="fm-role-subject">
              <ThemeIcon variant="light" color="blue" size="lg">
                <IconUserCheck size={19} />
              </ThemeIcon>
              <div>
                <Text fw={700}>{primitiveString(proxyUser?.display_name) || 'User'}</Text>
                <Text size="xs" c="dimmed">
                  {primitiveString(proxyUser?.email)}
                </Text>
              </div>
              <AppStatusBadge value="PROXY" label="Proxy session" />
            </div>
            <TextInput
              required
              label="Reason for proxying"
              description="This reason will be recorded in the audit log."
              placeholder="Investigating a reported access issue"
              value={proxyReason}
              onChange={(event) => setProxyReason(event.currentTarget.value)}
              autoFocus
            />
            <FeedbackMessage feedback={proxyFeedback} />
            <Group justify="flex-end" gap="sm">
              <Button
                type="button"
                variant="subtle"
                onClick={closeProxyDialog}
                disabled={proxySaving}
              >
                Cancel
              </Button>
              <Button type="submit" loading={proxySaving} disabled={!proxyReason.trim()}>
                Start proxy session
              </Button>
            </Group>
          </Stack>
        </form>
      </Dialog>
    </Stack>
  );
}

function AccessGrantsPage({
  snapshot,
  labels,
  onSaved,
  onRevoke,
}: {
  snapshot: AdministrationSnapshot;
  labels: Record<string, string>;
  onSaved: () => Promise<void>;
  onRevoke: (resource: string, row: Row) => void;
}) {
  const [editor, setEditor] = useState<GrantEditor | null>(null);
  const [grantQuery, setGrantQuery] = useState('');
  const [grantSort, setGrantSort] = useState<string | null>('ascending');
  const [grantGroup, setGrantGroup] = useState<string | null>(null);
  const [grantPolicy, setGrantPolicy] = useState<string | null>(null);
  const scopeRows = (rows: Row[]) =>
    rows.filter(
      (row) =>
        (!grantGroup || String(row.group_id) === grantGroup) &&
        (!grantPolicy || String(row.policy_id) === grantPolicy),
    );
  const policyGrantRows = scopeRows(snapshot.policy_delegations);
  const objectTypes = new Map(
    snapshot.objects.map((object) => [String(object.id), primitiveString(object.object_type)]),
  );
  const objectUseRows = (types: string[]) =>
    scopeRows(snapshot.object_use_grants)
      .filter((grant) => types.includes(objectTypes.get(String(grant.object_id)) ?? ''))
      .map((grant) => ({
        ...grant,
        object_type: objectTypes.get(String(grant.object_id)) ?? 'UNKNOWN',
      }));
  const networkObjectGrants = objectUseRows(['NETWORK', 'NETWORK_GROUP']);
  const portObjectGrants = objectUseRows(['PORT_SERVICE', 'PORT_SERVICE_GROUP']);
  const urlObjectGrants = objectUseRows(['URL', 'URL_GROUP']);
  const visibleObjectGrants = [...networkObjectGrants, ...portObjectGrants, ...urlObjectGrants];
  const visibleObjectCreateGrants = scopeRows(snapshot.object_create_grants).filter(
    (grant) => !['APPLICATION', 'APPLICATION_FILTER'].includes(primitiveString(grant.object_type)),
  );
  const boundaryGrants =
    scopeRows(snapshot.zone_grants).length + scopeRows(snapshot.ip_range_grants).length;
  const creationGrants = visibleObjectCreateGrants.length;
  return (
    <Stack gap="lg">
      <Alert color="blue" title="Immediate authorization changes">
        Grant updates apply on the next server-authorized request. They never enable real-provider
        writes or bypass Changeset controls.
      </Alert>
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <MetricCard
          label="Policy assignments"
          value={policyGrantRows.length}
          detail="Group policy access"
          icon={<IconShieldLock size={19} />}
        />
        <MetricCard
          label="Object permissions"
          value={visibleObjectGrants.length}
          detail="Network, port, and URL access"
          icon={<IconKey size={19} />}
        />
        <MetricCard
          label="Network boundaries"
          value={boundaryGrants}
          detail="Security zones and authorized ranges"
          icon={<IconLink size={19} />}
        />
        <MetricCard
          label="Creation rights"
          value={creationGrants}
          detail="Objects this Group may create"
          icon={<IconLink size={19} />}
        />
      </SimpleGrid>
      <Card>
        <AppSection
          title="Effective grant records"
          description="Open a record to refine its permissions, or revoke it immediately."
        >
          <div className="fm-list-toolbar fm-list-toolbar-grants">
            <TextInput
              aria-label="Search access grants"
              placeholder="Search grants"
              value={grantQuery}
              onChange={(event) => setGrantQuery(event.currentTarget.value)}
            />
            <Select
              aria-label="Filter grants by group"
              placeholder="All groups"
              value={grantGroup}
              onChange={setGrantGroup}
              clearable
              searchable
              data={[
                ...snapshot.groups
                  .map((group) => ({
                    value: String(group.id),
                    label: String(group.name ?? group.id),
                  }))
                  .sort((left, right) => left.label.localeCompare(right.label)),
              ]}
            />
            <Select
              aria-label="Filter grants by access policy"
              placeholder="All policies"
              value={grantPolicy}
              onChange={setGrantPolicy}
              clearable
              searchable
              data={[
                ...snapshot.policies
                  .map((policy) => ({
                    value: String(policy.id),
                    label: String(policy.name ?? policy.id),
                  }))
                  .sort((left, right) => left.label.localeCompare(right.label)),
              ]}
            />
            <Select
              aria-label="Sort access grants"
              value={grantSort}
              onChange={setGrantSort}
              allowDeselect={false}
              data={[
                { value: 'ascending', label: 'Sort: A–Z' },
                { value: 'descending', label: 'Sort: Z–A' },
              ]}
            />
          </div>
          <Tabs defaultValue="policy">
            <Tabs.List>
              <Tabs.Tab value="policy">Policy access</Tabs.Tab>
              <Tabs.Tab value="resources">Resource access</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="policy" pt="lg">
              <GrantTableSection
                title="Group policy grants"
                rows={policyGrantRows}
                fields={['group_id', 'policy_id', 'capabilities']}
                resource="policy-delegations"
                labels={labels}
                query={grantQuery}
                sort={grantSort}
                addLabel="Add group policy grant"
                onAdd={() => setEditor({ kind: 'policy-delegations' })}
                onRevoke={onRevoke}
                onEdit={(kind, row) => setEditor({ kind, row })}
              />
            </Tabs.Panel>
            <Tabs.Panel value="resources" pt="lg">
              <Tabs defaultValue="ip-ranges" className="fm-resource-grant-tabs">
                <Tabs.List>
                  <Tabs.Tab value="ip-ranges">IP ranges</Tabs.Tab>
                  <Tabs.Tab value="security-zones">Zones</Tabs.Tab>
                  <Tabs.Tab value="network-objects">Networks</Tabs.Tab>
                  <Tabs.Tab value="port-objects">Ports</Tabs.Tab>
                  <Tabs.Tab value="url-objects">URLs</Tabs.Tab>
                  <Tabs.Tab value="object-creation">Object creation</Tabs.Tab>
                </Tabs.List>
                <Tabs.Panel value="network-objects" pt="lg">
                  <GrantTableSection
                    title="Network objects"
                    rows={networkObjectGrants}
                    fields={['group_id', 'policy_id', 'object_id', 'object_type']}
                    resource="object-use-grants"
                    labels={labels}
                    query={grantQuery}
                    sort={grantSort}
                    addLabel="Add network object access"
                    onAdd={() =>
                      setEditor({
                        kind: 'object-use-grants',
                        objectTypes: ['NETWORK', 'NETWORK_GROUP'],
                      })
                    }
                    onRevoke={onRevoke}
                    onEdit={(kind, row) => setEditor({ kind, row })}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="port-objects" pt="lg">
                  <GrantTableSection
                    title="Port objects"
                    rows={portObjectGrants}
                    fields={['group_id', 'policy_id', 'object_id', 'object_type']}
                    resource="object-use-grants"
                    labels={labels}
                    query={grantQuery}
                    sort={grantSort}
                    addLabel="Add port object access"
                    onAdd={() =>
                      setEditor({
                        kind: 'object-use-grants',
                        objectTypes: ['PORT_SERVICE', 'PORT_SERVICE_GROUP'],
                      })
                    }
                    onRevoke={onRevoke}
                    onEdit={(kind, row) => setEditor({ kind, row })}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="url-objects" pt="lg">
                  <GrantTableSection
                    title="URL objects"
                    rows={urlObjectGrants}
                    fields={['group_id', 'policy_id', 'object_id', 'object_type']}
                    resource="object-use-grants"
                    labels={labels}
                    query={grantQuery}
                    sort={grantSort}
                    addLabel="Add URL object access"
                    onAdd={() =>
                      setEditor({ kind: 'object-use-grants', objectTypes: ['URL', 'URL_GROUP'] })
                    }
                    onRevoke={onRevoke}
                    onEdit={(kind, row) => setEditor({ kind, row })}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="security-zones" pt="lg">
                  <GrantTableSection
                    title="Security zones"
                    rows={scopeRows(snapshot.zone_grants)}
                    fields={['group_id', 'policy_id', 'zone_id', 'direction']}
                    resource="zone-grants"
                    labels={labels}
                    query={grantQuery}
                    sort={grantSort}
                    addLabel="Add security zone access"
                    onAdd={() => setEditor({ kind: 'zone-grants' })}
                    onRevoke={onRevoke}
                    onEdit={(kind, row) => setEditor({ kind, row })}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="ip-ranges" pt="lg">
                  <GrantTableSection
                    title="IP ranges"
                    rows={scopeRows(snapshot.ip_range_grants)}
                    fields={['group_id', 'policy_id', 'network']}
                    resource="ip-range-grants"
                    labels={labels}
                    query={grantQuery}
                    sort={grantSort}
                    addLabel="Add authorized IP range"
                    onAdd={() => setEditor({ kind: 'ip-range-grants' })}
                    onRevoke={onRevoke}
                    onEdit={(kind, row) => setEditor({ kind, row })}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="object-creation" pt="lg">
                  <GrantTableSection
                    title="Object creation"
                    rows={visibleObjectCreateGrants}
                    fields={['group_id', 'policy_id', 'object_type']}
                    resource="object-create-grants"
                    labels={labels}
                    query={grantQuery}
                    sort={grantSort}
                    addLabel="Add object creation right"
                    onAdd={() => setEditor({ kind: 'object-create-grants' })}
                    onRevoke={onRevoke}
                    onEdit={(kind, row) => setEditor({ kind, row })}
                  />
                </Tabs.Panel>
              </Tabs>
            </Tabs.Panel>
          </Tabs>
        </AppSection>
      </Card>
      <Dialog
        opened={editor !== null}
        onClose={() => setEditor(null)}
        title={
          editor?.row
            ? grantIsMutable(editor.kind)
              ? 'Modify access grant'
              : 'Access grant details'
            : grantAddTitle(editor)
        }
        closeButtonProps={{ 'aria-label': 'Close' }}
        classNames={{
          content: 'fm-management-modal',
          header: 'fm-management-modal-header',
          body: 'fm-management-modal-body',
        }}
        size="xl"
        centered
      >
        {editor && (
          <GrantForm
            key={`${editor.kind}-${editor.objectTypes?.join('-') ?? ''}-${primitiveString(editor.row?.id, 'new')}`}
            snapshot={snapshot}
            onSaved={onSaved}
            initial={editor}
            onCompleted={() => setEditor(null)}
          />
        )}
      </Dialog>
    </Stack>
  );
}

function CreateIdentityForm({
  resource,
  onSaved,
  onCompleted,
}: {
  resource: 'users' | 'groups';
  onSaved: () => Promise<void>;
  onCompleted: () => void;
}) {
  const isUser = resource === 'users';
  const [primary, setPrimary] = useState('');
  const [secondary, setSecondary] = useState('');
  const [role, setRole] = useState<string | null>('user');
  const [approvalRequired, setApprovalRequired] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    setFeedback(null);
    setSaving(true);
    const payload = isUser
      ? {
          display_name: primary.trim(),
          email: secondary.trim(),
          role: role ?? 'user',
        }
      : {
          name: primary.trim(),
          provider_slug: secondary.trim().toUpperCase(),
          approval_required: approvalRequired,
        };
    try {
      await createAdministrativeResource(resource, payload);
      await onSaved();
      if (isUser) window.dispatchEvent(new Event(developmentIdentitiesChangedEvent));
      setPrimary('');
      setSecondary('');
      onCompleted();
    } catch (error) {
      setFeedback({ kind: 'error', message: errorMessage(error) });
    } finally {
      setSaving(false);
    }
  };
  return (
    <form
      onSubmit={(event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        void submit();
      }}
    >
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          {isUser
            ? 'Register a control-plane identity. Group membership and resource access are assigned separately.'
            : 'Create a stable ownership boundary for provider naming and policy grants.'}
        </Text>
        <TextInput
          required
          label={isUser ? 'Display name' : 'Group name'}
          placeholder={isUser ? 'Jordan Lee' : 'Network Engineering'}
          value={primary}
          onChange={(event) => setPrimary(event.currentTarget.value)}
        />
        <TextInput
          required
          type={isUser ? 'email' : 'text'}
          label={isUser ? 'Email address' : 'Stable provider prefix'}
          description={
            isUser
              ? 'User-facing attribute; it is not used as the OIDC security identity.'
              : 'Uppercase prefix used for provider-owned names; cannot be changed casually.'
          }
          placeholder={isUser ? 'jordan@example.com' : 'NETENG'}
          value={secondary}
          onChange={(event) => setSecondary(event.currentTarget.value)}
        />
        {isUser && (
          <Text size="xs" c="dimmed">
            The OIDC identity is linked automatically when this email address signs in for the first
            time.
          </Text>
        )}
        {isUser && (
          <Select
            label="Application role"
            description="Select a role to see its platform capabilities. Group memberships and policy grants control access."
            value={role}
            onChange={setRole}
            data={roleOptions}
            allowDeselect={false}
          />
        )}
        {isUser && <RoleDescription role={role} />}
        {!isUser && (
          <Checkbox
            label="Require Changeset approval"
            description="Group members must have a separate approver approve each validated Changeset before execution."
            checked={approvalRequired}
            onChange={(event) => setApprovalRequired(event.currentTarget.checked)}
          />
        )}
        <FeedbackMessage feedback={feedback} />
        <Button type="submit" loading={saving} disabled={!primary.trim() || !secondary.trim()}>
          Create {isUser ? 'User' : 'Group'}
        </Button>
      </Stack>
    </form>
  );
}

function RoleManager({
  user,
  onSaved,
  onClose,
}: {
  user: Row | null;
  onSaved: () => Promise<void>;
  onClose: () => void;
}) {
  const [role, setRole] = useState<string | null>(() =>
    user ? primitiveString(user.role) : 'user',
  );
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const save = async () => {
    if (!user || !role || role === primitiveString(user.role)) return;
    setSaving(true);
    setFeedback(null);
    try {
      await updateAdministrativeUserRole(String(user.id), role, Number(user.revision));
      await onSaved();
      onClose();
    } catch (error) {
      setFeedback({ kind: 'error', message: errorMessage(error) });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog
      opened={Boolean(user)}
      onClose={onClose}
      title="Change User Role"
      closeButtonProps={{ 'aria-label': 'Close' }}
      classNames={{
        content: 'fm-management-modal',
        header: 'fm-management-modal-header',
        body: 'fm-management-modal-body',
      }}
      centered
    >
      <form
        onSubmit={(event: React.FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          void save();
        }}
      >
        <Stack gap="md">
          <div className="fm-role-subject">
            <ThemeIcon variant="light" color="blue" size="lg">
              <IconShieldLock size={19} />
            </ThemeIcon>
            <div>
              <Text fw={700}>{primitiveString(user?.display_name) || 'User'}</Text>
              <Text size="xs" c="dimmed">
                {primitiveString(user?.email)}
              </Text>
            </div>
            <AppStatusBadge
              value={primitiveString(user?.role)}
              label={roleLabel(primitiveString(user?.role))}
            />
          </div>
          <Select
            label="Application role"
            description="Select a role to see its platform capabilities. Group memberships and policy grants control access."
            value={role}
            onChange={setRole}
            data={roleOptions}
            allowDeselect={false}
          />
          <RoleDescription role={role} />
          <FeedbackMessage feedback={feedback} />
          <Button
            type="submit"
            loading={saving}
            disabled={!role || role === primitiveString(user?.role)}
          >
            Save Role
          </Button>
        </Stack>
      </form>
    </Dialog>
  );
}

function MembershipManager({
  mode,
  subject,
  snapshot,
  onSaved,
  onClose,
}: {
  mode: 'user' | 'group';
  subject: Row | null;
  snapshot: AdministrationSnapshot;
  onSaved: () => Promise<void>;
  onClose: () => void;
}) {
  const [query, setQuery] = useState('');
  const [assignmentFilter, setAssignmentFilter] = useState<string | null>('all');
  const [assignmentSort, setAssignmentSort] = useState<string | null>('name');
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const candidates = mode === 'user' ? snapshot.groups : snapshot.users;
  const candidateLabel = mode === 'user' ? 'name' : 'display_name';
  const membershipFor = (candidate: Row) =>
    snapshot.memberships.find((membership) =>
      mode === 'user'
        ? String(membership.user_id) === String(subject?.id) &&
          String(membership.group_id) === String(candidate.id)
        : String(membership.group_id) === String(subject?.id) &&
          String(membership.user_id) === String(candidate.id),
    );
  const assignedCount = candidates.filter((candidate) => membershipFor(candidate)).length;
  const filtered = [
    ...filterRows(
      candidates,
      query,
      mode === 'user' ? ['name', 'provider_slug'] : ['display_name', 'email', 'role'],
    ),
  ]
    .filter((candidate) => {
      if (assignmentFilter === 'assigned') return Boolean(membershipFor(candidate));
      if (assignmentFilter === 'available') return !membershipFor(candidate);
      return true;
    })
    .sort((left, right) => {
      const leftAssigned = membershipFor(left) ? 1 : 0;
      const rightAssigned = membershipFor(right) ? 1 : 0;
      if (assignmentSort === 'assigned' && leftAssigned !== rightAssigned) {
        return rightAssigned - leftAssigned;
      }
      if (assignmentSort === 'available' && leftAssigned !== rightAssigned) {
        return leftAssigned - rightAssigned;
      }
      return primitiveString(left[candidateLabel]).localeCompare(
        primitiveString(right[candidateLabel]),
        undefined,
        { sensitivity: 'base' },
      );
    });

  const changeMembership = async (candidate: Row) => {
    if (!subject) return;
    const membership = membershipFor(candidate);
    const candidateId = String(candidate.id);
    if (
      membership &&
      !window.confirm('Remove this membership? The access change takes effect immediately.')
    ) {
      return;
    }
    setBusyId(candidateId);
    setFeedback(null);
    try {
      if (membership) {
        await revokeAuthorizationResource(
          'memberships',
          String(membership.id),
          Number(membership.revision),
        );
      } else {
        const payload: Row = {
          user_id: mode === 'user' ? subject.id : candidate.id,
          group_id: mode === 'group' ? subject.id : candidate.id,
          status: 'ACTIVE',
        };
        const expectedRevision = authorizationExpectedRevision(snapshot, 'memberships', payload);
        if (expectedRevision !== undefined) payload.expected_revision = expectedRevision;
        await upsertAuthorizationResource('memberships', payload);
      }
      await onSaved();
      setFeedback({
        kind: 'success',
        message: membership ? 'Membership removed.' : 'Membership added.',
      });
    } catch (error) {
      setFeedback({ kind: 'error', message: errorMessage(error) });
    } finally {
      setBusyId(null);
    }
  };

  const subjectName = primitiveString(
    subject?.[mode === 'user' ? 'display_name' : 'name'],
    mode === 'user' ? 'User' : 'Group',
  );
  const close = () => {
    setQuery('');
    setAssignmentFilter('all');
    setAssignmentSort('name');
    setFeedback(null);
    onClose();
  };
  return (
    <Dialog
      opened={subject !== null}
      onClose={close}
      title={mode === 'user' ? 'Manage Groups' : 'Manage members'}
      closeButtonProps={{ 'aria-label': 'Close' }}
      classNames={{
        content: 'fm-management-modal',
        header: 'fm-management-modal-header',
        body: 'fm-management-modal-body',
      }}
      size="lg"
      centered
    >
      <Stack gap="md">
        <div className="fm-membership-subject">
          <ThemeIcon variant="light" color="blue" size="lg">
            {initials(subjectName)}
          </ThemeIcon>
          <div className="fm-membership-identity">
            <Text fw={700}>{subjectName}</Text>
            <Text size="sm" c="dimmed">
              {assignedCount} {assignedCount === 1 ? 'assignment' : 'assignments'}
            </Text>
            <Text size="xs" c="dimmed">
              {mode === 'user'
                ? 'Groups define the ownership contexts this User can work through.'
                : 'Members can select this Group when working with policy grants.'}
            </Text>
          </div>
          <div className="fm-membership-subject-status">
            <AppStatusBadge
              value={subject?.enabled ? 'HEALTHY' : 'DISABLED'}
              label={subject?.enabled ? 'Active' : 'Disabled'}
            />
          </div>
        </div>
        <div className="fm-membership-toolbar">
          <TextInput
            aria-label={mode === 'user' ? 'Search available Groups' : 'Search available Users'}
            placeholder={mode === 'user' ? 'Search Groups' : 'Search Users'}
            value={query}
            onChange={(event) => setQuery(event.currentTarget.value)}
          />
          <Select
            aria-label="Filter memberships"
            value={assignmentFilter}
            onChange={setAssignmentFilter}
            allowDeselect={false}
            data={[
              { value: 'all', label: 'Show all' },
              { value: 'assigned', label: 'Assigned only' },
              { value: 'available', label: 'Available only' },
            ]}
          />
          <Select
            aria-label="Sort memberships"
            value={assignmentSort}
            onChange={setAssignmentSort}
            allowDeselect={false}
            data={[
              { value: 'name', label: 'Sort: Name' },
              { value: 'assigned', label: 'Assigned first' },
              { value: 'available', label: 'Available first' },
            ]}
          />
        </div>
        <div className="fm-membership-list">
          {filtered.length === 0 ? (
            <AppEmptyState title="No matches" description="Try a different search term." />
          ) : (
            filtered.map((candidate) => {
              const membership = membershipFor(candidate);
              const id = String(candidate.id);
              return (
                <div className="fm-membership-row" key={id}>
                  <ThemeIcon className="fm-member-icon" variant="light" color="gray" size="lg">
                    {initials(primitiveString(candidate[candidateLabel]))}
                  </ThemeIcon>
                  <div className="fm-membership-identity">
                    <Text fw={650}>{primitiveString(candidate[candidateLabel])}</Text>
                    <Text size="xs" c="dimmed">
                      {mode === 'user'
                        ? primitiveString(candidate.provider_slug)
                        : `${primitiveString(candidate.email)} · ${humanize(primitiveString(candidate.role))}`}
                    </Text>
                  </div>
                  <div
                    className={`fm-membership-state ${
                      membership ? 'fm-membership-state-assigned' : 'fm-membership-state-available'
                    }`}
                  >
                    <AppStatusBadge
                      value={membership ? 'ASSIGNED' : 'AVAILABLE'}
                      label={membership ? 'Assigned' : 'Available'}
                      size="xs"
                    />
                  </div>
                  <div className="fm-membership-action">
                    <ActionButton
                      className="fm-membership-action-control"
                      intent={membership ? 'danger' : 'success'}
                      loading={busyId === id}
                      disabled={!membership && candidate.enabled === false}
                      onClick={() => void changeMembership(candidate)}
                    >
                      {membership ? 'Remove' : 'Add'}
                    </ActionButton>
                  </div>
                </div>
              );
            })
          )}
        </div>
        <FeedbackMessage feedback={feedback} />
      </Stack>
    </Dialog>
  );
}

const grantKinds = [
  ['policy-delegations', 'Group policy grant'],
  ['object-use-grants', 'Object access'],
  ['zone-grants', 'Security zone'],
  ['ip-range-grants', 'IP range'],
  ['object-create-grants', 'Object creation'],
] as const;

const capabilityOptions = [
  { value: 'view', label: 'View policy' },
  { value: 'create_rule', label: 'Create rules' },
  { value: 'modify_rule', label: 'Modify rules' },
  { value: 'delete_rule', label: 'Delete rules' },
  { value: 'reorder_rule', label: 'Reorder rules' },
  { value: 'modify_object', label: 'Modify objects' },
  { value: 'delete_object', label: 'Delete objects' },
];

function GrantForm({
  snapshot,
  onSaved,
  initial,
  onCompleted,
}: {
  snapshot: AdministrationSnapshot;
  onSaved: () => Promise<void>;
  initial: GrantEditor;
  onCompleted: () => void;
}) {
  const [kind, setKind] = useState<string>(initial.kind);
  const [groupId, setGroupId] = useState<string | null>(nullableString(initial.row?.group_id));
  const [policyId, setPolicyId] = useState<string | null>(nullableString(initial.row?.policy_id));
  const [resourceId, setResourceId] = useState<string | null>(
    initialResourceId(initial.kind, initial.row),
  );
  const [value, setValue] = useState(initialGrantValue(initial.kind, initial.row));
  const [capabilities, setCapabilities] = useState<string[]>(
    Array.isArray(initial.row?.capabilities)
      ? initial.row.capabilities.map((item) => primitiveString(item)).filter(Boolean)
      : ['view'],
  );
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [saving, setSaving] = useState(false);
  const resourceOptions = useMemo(() => {
    const resources = providerResourcesForPolicy(snapshot, kind, policyId);
    const filteredResources = initial.objectTypes?.length
      ? resources.filter((resource) =>
          initial.objectTypes?.includes(primitiveString(resource.object_type)),
        )
      : resources;
    return filteredResources
      .filter((resource) => resource.enabled !== false)
      .map((resource) => ({
        value: String(resource.id),
        label:
          kind === 'object-use-grants'
            ? `${String(resource.name ?? resource.id)} (${objectTypeLabel(primitiveString(resource.object_type))})`
            : String(resource.name ?? resource.id),
      }));
  }, [snapshot, kind, policyId, initial.objectTypes]);
  const resourceRequired = ['object-use-grants', 'zone-grants'].includes(kind);
  const capabilityGrant = kind === 'policy-delegations';
  const editing = Boolean(initial.row);
  const mutableGrant = grantIsMutable(kind);
  const valueRequired = ['ip-range-grants', 'object-create-grants'].includes(kind);
  const canSubmit =
    Boolean(groupId && policyId) &&
    (!resourceRequired || Boolean(resourceId)) &&
    (!valueRequired || Boolean(value.trim())) &&
    (!capabilityGrant || capabilities.length > 0);

  const resetDependentFields = () => {
    setPolicyId(null);
    setResourceId(null);
    setValue('');
    setCapabilities(['view']);
    setFeedback(null);
  };
  const submit = async () => {
    if (!canSubmit) return;
    const payload: Row = { group_id: groupId, policy_id: policyId };
    if (capabilityGrant) {
      payload.capabilities = capabilities;
      payload.is_active = true;
    } else if (kind === 'object-use-grants') {
      payload.object_id = resourceId;
      payload.permission = 'use';
    } else if (kind === 'zone-grants') {
      if (editing) payload.id = initial.row?.id;
      payload.zone_id = resourceId;
      payload.direction = value || 'BOTH';
    } else if (kind === 'ip-range-grants') payload.network = value.trim();
    else if (kind === 'object-create-grants') payload.object_type = value;
    const expectedRevision = authorizationExpectedRevision(snapshot, kind, payload);
    if (expectedRevision !== undefined) payload.expected_revision = expectedRevision;
    setSaving(true);
    setFeedback(null);
    try {
      await upsertAuthorizationResource(kind, payload);
      await onSaved();
      onCompleted();
    } catch (error) {
      setFeedback({ kind: 'error', message: errorMessage(error) });
    } finally {
      setSaving(false);
    }
  };
  return (
    <form
      onSubmit={(event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        void submit();
      }}
    >
      <Text size="sm" c="dimmed" maw={620} mb="md">
        Select a subject and policy boundary. Existing records retain their logical scope while
        their grant details are updated.
      </Text>
      <div className="fm-form-section">
        <Text className="fm-form-section-label">1 · Grant type</Text>
        <Select
          label="Authorization record"
          value={kind}
          onChange={(selected) => {
            setKind(selected ?? 'policy-delegations');
            resetDependentFields();
          }}
          data={grantKinds.map(([itemValue, label]) => ({ value: itemValue, label }))}
          allowDeselect={false}
          disabled
        />
      </div>
      <div className="fm-form-section">
        <Text className="fm-form-section-label">2 · Subject and scope</Text>
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <Select
            searchable
            label="Group context"
            placeholder="Choose a group"
            value={groupId}
            onChange={setGroupId}
            data={options(snapshot.groups, 'name')}
            disabled={editing}
          />
          <Select
            searchable
            label="Access policy"
            placeholder="Choose a policy"
            value={policyId}
            onChange={(selected) => {
              setPolicyId(selected);
              setResourceId(null);
            }}
            data={options(snapshot.policies, 'name')}
            disabled={editing}
          />
        </SimpleGrid>
      </div>
      <div className="fm-form-section">
        <Text className="fm-form-section-label">3 · Permission details</Text>
        {capabilityGrant && (
          <MultiSelect
            searchable
            label="Capabilities"
            description="Each capability is independently checked by the server."
            placeholder="Select capabilities"
            value={capabilities}
            onChange={setCapabilities}
            data={capabilityOptions}
          />
        )}
        {resourceOptions.length > 0 && (
          <Select
            searchable
            label={resourceLabel(kind)}
            placeholder="Choose a provider resource"
            value={resourceId}
            onChange={setResourceId}
            data={resourceOptions}
            disabled={editing}
          />
        )}
        {kind === 'zone-grants' && (
          <Select
            label="Traffic direction"
            value={value || 'BOTH'}
            onChange={(selected) => setValue(selected ?? 'BOTH')}
            data={[
              { value: 'BOTH', label: 'Source and destination' },
              { value: 'SOURCE', label: 'Source only' },
              { value: 'DESTINATION', label: 'Destination only' },
            ]}
            allowDeselect={false}
            disabled={editing && kind !== 'zone-grants'}
          />
        )}
        {kind === 'ip-range-grants' && (
          <TextInput
            label="Authorized network"
            description="Enter an IPv4 or IPv6 host, CIDR subnet, or ordered range."
            placeholder="10.20.0.0/16, 2001:db8::/32, or 2001:db8::1-2001:db8::ff"
            value={value}
            onChange={(event) => setValue(event.currentTarget.value)}
            disabled={editing}
          />
        )}
        {kind === 'object-create-grants' && (
          <Select
            label="Object type"
            description="Each grant includes the corresponding object group type. Network includes network groups, Port includes port groups, and URL includes URL groups."
            placeholder="Choose an object type"
            value={value || null}
            onChange={(selected) => setValue(selected ?? '')}
            data={[
              { value: 'NETWORK', label: 'Network' },
              { value: 'PORT_SERVICE', label: 'Port' },
              { value: 'URL', label: 'URL' },
            ]}
            disabled={editing}
          />
        )}
        {kind === 'object-use-grants' && !policyId && (
          <Text size="sm" c="dimmed">
            Choose a policy to load objects from its provider manager.
          </Text>
        )}
        {editing && !mutableGrant && (
          <Alert color="blue" mt="sm">
            This grant's scope is its identity and cannot be edited in place. Revoke it and add a
            replacement to change the scope.
          </Alert>
        )}
      </div>
      <Group justify="space-between" align="end" mt="lg">
        <FeedbackMessage feedback={feedback} />
        {(!editing || mutableGrant) && (
          <Button type="submit" loading={saving} disabled={!canSubmit}>
            {editing ? 'Update access grant' : 'Add access grant'}
          </Button>
        )}
      </Group>
    </form>
  );
}

function GrantTableSection({
  title,
  rows,
  fields,
  resource,
  labels,
  query,
  sort,
  addLabel,
  onAdd,
  onRevoke,
  onEdit,
}: {
  title: string;
  rows: Row[];
  fields: string[];
  resource: string;
  labels: Record<string, string>;
  query: string;
  sort: string | null;
  addLabel: string;
  onAdd: () => void;
  onRevoke: (resource: string, row: Row) => void;
  onEdit: (resource: string, row: Row) => void;
}) {
  const [page, setPage] = useState(1);
  const pageSize = useAdaptivePageSize();
  const normalizedQuery = query.trim().toLowerCase();
  const filteredRows = [...rows]
    .filter((row) =>
      normalizedQuery
        ? fields.some((field) => grantSearchValue(row[field], labels).includes(normalizedQuery))
        : true,
    )
    .sort((left, right) => {
      const leftValue = fields.map((field) => grantSearchValue(left[field], labels)).join(' ');
      const rightValue = fields.map((field) => grantSearchValue(right[field], labels)).join(' ');
      const direction = sort === 'descending' ? -1 : 1;
      return leftValue.localeCompare(rightValue, undefined, { sensitivity: 'base' }) * direction;
    });
  useEffect(() => {
    setPage(1);
  }, [query, sort, rows.length]);
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visibleRows = filteredRows.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  return (
    <div className="fm-grant-section">
      <AppSection
        title={title}
        actions={
          <Group gap="sm" wrap="wrap">
            <AppStatusBadge
              value="COUNT"
              label={
                normalizedQuery
                  ? `${filteredRows.length} of ${rows.length}`
                  : `${rows.length} ${rows.length === 1 ? 'record' : 'records'}`
              }
            />
            <Button leftSection={<IconPlus size={16} />} onClick={onAdd}>
              {addLabel}
            </Button>
          </Group>
        }
      >
        <AdminTable
          label={`${title} table`}
          rows={visibleRows}
          fields={fields}
          labels={labels}
          tone="grants"
          actions={(row) => (
            <Group gap="xs" wrap="nowrap">
              <ActionButton
                intent="secondary"
                leftSection={<IconEdit size={14} />}
                onClick={() => onEdit(resource, row)}
              >
                {grantIsMutable(resource) ? 'Modify' : 'Review'}
              </ActionButton>
              <ActionButton intent="danger" onClick={() => onRevoke(resource, row)}>
                Revoke
              </ActionButton>
            </Group>
          )}
        />
      </AppSection>
      <AdaptivePagination
        page={currentPage}
        pageSize={pageSize}
        total={filteredRows.length}
        onPageChange={setPage}
      />
    </div>
  );
}

function AdminTable({
  label,
  rows,
  fields,
  actions,
  labels = {},
  tone,
}: {
  label: string;
  rows: Row[];
  fields: string[];
  actions?: (row: Row) => ReactNode;
  labels?: Record<string, string>;
  tone?: 'users' | 'groups' | 'grants';
}) {
  if (rows.length === 0) {
    return (
      <AppEmptyState
        title="No records"
        description={`There are no ${label.toLowerCase()} matching this view.`}
      />
    );
  }
  return (
    <div className={tone ? `fm-directory-table fm-directory-table-${tone}` : undefined}>
      <AppDataTable label={label}>
        <Table.Thead>
          <Table.Tr>
            {fields.map((field) => (
              <Table.Th key={field}>{fieldLabels[field] ?? humanize(field)}</Table.Th>
            ))}
            {actions && <Table.Th>Actions</Table.Th>}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.map((row) => (
            <Table.Tr key={String(row.id)}>
              {fields.map((field) => (
                <Table.Td key={field}>{formatValue(field, row[field], labels)}</Table.Td>
              ))}
              {actions && <Table.Td>{actions(row)}</Table.Td>}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </AppDataTable>
    </div>
  );
}

type Feedback = { kind: 'success' | 'error'; message: string };

function FeedbackMessage({ feedback }: { feedback: Feedback | null }) {
  if (!feedback) return <span />;
  return (
    <Text
      role={feedback.kind === 'error' ? 'alert' : 'status'}
      c={feedback.kind === 'error' ? 'red' : 'teal'}
      size="sm"
    >
      {feedback.message}
    </Text>
  );
}

const roleOptions = [
  { value: 'user', label: 'User' },
  { value: 'approver', label: 'Approver' },
  { value: 'firewall_operator', label: 'Firewall operator' },
  { value: 'admin', label: 'Platform administrator' },
];

const roleDescriptions: Record<string, { title: string; description: string }> = {
  user: {
    title: 'User capabilities',
    description:
      'Can sign in and view the assigned workspace. Can create or modify rules and objects only when Group membership and policy grants allow it. Cannot manage users, grants, providers, or approvals.',
  },
  approver: {
    title: 'Approver capabilities',
    description:
      'Can review, approve, and reject Changesets. Group membership and policy grants still control rule and object access. Cannot manage users, grants, or provider connections.',
  },
  firewall_operator: {
    title: 'Firewall operator capabilities',
    description:
      'Has broad firewall operational authority, including inventory, reconciliation, deployment, and Changeset approval or rejection. Cannot manage users, access grants, or provider connections.',
  },
  admin: {
    title: 'Platform administrator capabilities',
    description:
      'Full platform authority, including users, Groups, access grants, provider connections, firewall operations, deployments, and Changesets.',
  },
};

function RoleDescription({ role }: { role: string | null }) {
  const selected = role ? roleDescriptions[role] : undefined;
  if (!selected) return null;
  return (
    <div className="fm-role-capability">
      <Text fw={700} size="sm">
        {selected.title}
      </Text>
      <Text size="sm" c="dimmed">
        {selected.description}
      </Text>
    </div>
  );
}

function roleLabel(value: string) {
  return roleOptions.find((option) => option.value === value)?.label ?? value;
}

const fieldLabels: Record<string, string> = {
  display_name: 'User',
  provider_slug: 'Provider prefix',
  user_id: 'User',
  group_id: 'Group',
  policy_id: 'Access policy',
  object_id: 'Object',
  zone_id: 'Security zone',
  category_id: 'Provider category',
  expected_category_name: 'Expected name',
  object_type: 'Object type',
  sync_state: 'Sync state',
  member_count: 'Members',
  group_count: 'Groups',
  approval_required: 'Changeset approval',
};

function formatValue(field: string, value: unknown, labels: Record<string, string>): ReactNode {
  if (field === 'enabled') {
    return (
      <AppStatusBadge
        value={value ? 'HEALTHY' : 'DISABLED'}
        label={value ? 'Active' : 'Disabled'}
      />
    );
  }
  if (field === 'approval_required') {
    return (
      <AppStatusBadge
        value={value ? 'REQUIRED' : 'READY'}
        label={value ? 'Required' : 'Not required'}
      />
    );
  }
  if (field === 'direction') {
    const direction = primitiveString(value, 'UNKNOWN');
    const directionLabels: Record<string, string> = {
      SOURCE: 'Source only',
      DESTINATION: 'Destination only',
      BOTH: 'Source and destination',
    };
    return (
      <AppStatusBadge
        value={`DIRECTION_${direction}`}
        label={directionLabels[direction] ?? humanize(direction)}
      />
    );
  }
  if (field === 'object_type') {
    const objectType = primitiveString(value, 'UNKNOWN');
    return <AppStatusBadge value="OBJECT_TYPE" label={objectTypeLabel(objectType)} />;
  }
  if (field === 'status' || field === 'sync_state') {
    return <AppStatusBadge value={primitiveString(value, 'UNKNOWN')} />;
  }
  if (field === 'role') return humanize(primitiveString(value));
  if (field === 'member_count') {
    const count = Number(value);
    return (
      <AppStatusBadge value="COUNT" label={`${count} ${count === 1 ? 'member' : 'members'}`} />
    );
  }
  if (field === 'group_count') {
    const count = Number(value);
    return <AppStatusBadge value="COUNT" label={`${count} ${count === 1 ? 'group' : 'groups'}`} />;
  }
  if (field === 'capabilities' && Array.isArray(value)) {
    return (
      <AppStatusBadge
        value="COUNT"
        label={`${value.length} ${value.length === 1 ? 'capability' : 'capabilities'}`}
      />
    );
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <Text c="dimmed">None</Text>;
    return (
      <Group gap={5} wrap="wrap">
        {value.map((item) => (
          <AppStatusBadge
            key={String(item)}
            value="ACTIVE"
            label={labels[String(item)] ?? humanize(String(item))}
            size="xs"
          />
        ))}
      </Group>
    );
  }
  if (value === null || value === undefined) return '—';
  if (typeof value === 'object') return 'Structured value';
  const scalar = primitiveString(value);
  const rendered = labels[scalar] ?? scalar;
  return field.endsWith('_id') || !(field in humanizedFields) ? rendered : humanize(rendered);
}

const humanizedFields: Record<string, true> = {
  role: true,
  permission: true,
  direction: true,
  object_type: true,
};

function options(rows: Row[], label: string) {
  return rows
    .filter((row) => row.enabled !== false)
    .map((row) => ({ value: String(row.id), label: String(row[label] ?? row.id) }));
}

function nullableString(value: unknown): string | null {
  const rendered = primitiveString(value);
  return rendered || null;
}

function initialResourceId(kind: string, row?: Row): string | null {
  if (kind === 'object-use-grants') return nullableString(row?.object_id);
  if (kind === 'zone-grants') return nullableString(row?.zone_id);
  return null;
}

function initialGrantValue(kind: string, row?: Row) {
  if (kind === 'object-use-grants') return primitiveString(row?.permission, 'use');
  if (kind === 'zone-grants') return primitiveString(row?.direction, 'BOTH');
  if (kind === 'ip-range-grants') return primitiveString(row?.network);
  if (kind === 'object-create-grants') return primitiveString(row?.object_type);
  return '';
}

function resourceLabel(kind: string) {
  if (kind === 'object-use-grants') return 'Firewall object';
  if (kind === 'zone-grants') return 'Security zone';
  return 'Provider resource';
}

function grantIsMutable(kind: string) {
  return ['policy-delegations', 'zone-grants'].includes(kind);
}

function grantAddTitle(editor: GrantEditor | null) {
  if (!editor) return 'Add access grant';
  if (editor.objectTypes?.includes('NETWORK')) return 'Add network object access';
  if (editor.objectTypes?.includes('PORT_SERVICE')) return 'Add port object access';
  if (editor.objectTypes?.includes('URL')) return 'Add URL object access';
  const titles: Record<string, string> = {
    'policy-delegations': 'Add group policy grant',
    'zone-grants': 'Add security zone access',
    'ip-range-grants': 'Add authorized IP range',
    'object-create-grants': 'Add object creation right',
  };
  return titles[editor.kind] ?? 'Add access grant';
}

function filterRows(rows: Row[], query: string, fields: string[]) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return rows;
  return rows.filter((row) =>
    fields.some((field) => {
      const value = row[field];
      const searchable = Array.isArray(value)
        ? value.map((item) => primitiveString(item)).join(' ')
        : primitiveString(value);
      return searchable.toLowerCase().includes(normalized);
    }),
  );
}

function grantSearchValue(value: unknown, labels: Record<string, string>) {
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        const scalar = primitiveString(item);
        return labels[scalar] ?? humanize(scalar);
      })
      .join(' ')
      .toLowerCase();
  }
  const scalar = primitiveString(value);
  return (labels[scalar] ?? humanize(scalar)).toLowerCase();
}

function primitiveString(value: unknown, fallback = '') {
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean' ||
    typeof value === 'bigint'
  ) {
    return String(value);
  }
  return fallback;
}

function resourceLabels(snapshot: AdministrationSnapshot) {
  const labels: Record<string, string> = {};
  for (const [rows, field] of [
    [snapshot.users, 'display_name'],
    [snapshot.groups, 'name'],
    [snapshot.policies, 'name'],
    [snapshot.objects, 'name'],
    [snapshot.zones, 'name'],
    [snapshot.categories, 'name'],
  ] as const) {
    for (const row of rows) labels[String(row.id)] = String(row[field] ?? row.id);
  }
  return labels;
}

function humanize(value: string) {
  if (/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(value)) return 'Internal resource';
  return value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function objectTypeLabel(value: string) {
  const labels: Record<string, string> = {
    NETWORK: 'Network',
    NETWORK_GROUP: 'Network group',
    PORT_SERVICE: 'Port',
    PORT_SERVICE_GROUP: 'Port group',
    URL: 'URL',
    URL_GROUP: 'URL group',
    APPLICATION: 'Application',
    APPLICATION_FILTER: 'Application filter',
  };
  return labels[value] ?? humanize(value);
}

function initials(value: string) {
  const letters = value
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('');
  return letters || '—';
}

function errorMessage(error: unknown) {
  if (error instanceof ApiError && error.code === 'NETWORK_OBJECT_OUTSIDE_ASSIGNED_IP_RANGES') {
    return 'This network object is outside the Group’s assigned IP ranges and cannot be assigned.';
  }
  return error instanceof Error ? error.message : 'The record could not be saved.';
}

function toError(error: unknown): State {
  return error instanceof ApiError
    ? { status: 'error', message: error.message, correlationId: error.correlationId }
    : { status: 'error', message: 'Authorization administration is unavailable.' };
}
