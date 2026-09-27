import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  IconBuildingCommunity,
  IconEdit,
  IconKey,
  IconLink,
  IconPlus,
  IconShieldLock,
  IconUserCheck,
  IconUserPlus,
  IconUsers,
} from '@tabler/icons-react';

import {
  ApiError,
  createAdministrativeResource,
  loadAdministration,
  revokeAuthorizationResource,
  updateAdministrativeEnabled,
  updateAdministrativeUserRole,
  upsertAuthorizationResource,
  type AdministrationSnapshot,
} from '../../api/client';
import {
  AppAlert as Alert,
  AppActionButton as ActionButton,
  AppButton as Button,
  AppCard as Card,
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
}: {
  snapshot: AdministrationSnapshot;
  labels: Record<string, string>;
  onSaved: () => Promise<void>;
  onToggle: (row: Row) => void;
}) {
  const [query, setQuery] = useState('');
  const [createOpened, setCreateOpened] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState<Row | null>(null);
  const active = snapshot.groups.filter((row) => Boolean(row.enabled)).length;
  const groupRows = snapshot.groups.map((group) => ({
    ...group,
    member_names: snapshot.memberships
      .filter((membership) => String(membership.group_id) === String(group.id))
      .map((membership) => labels[String(membership.user_id)] ?? 'Unknown user'),
    member_count: snapshot.memberships.filter(
      (membership) => String(membership.group_id) === String(group.id),
    ).length,
  }));
  const filtered = filterRows(groupRows, query, ['name', 'provider_slug', 'member_names']);
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
          label="Delegated groups"
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
                  query ? `${filtered.length} of ${groupRows.length}` : `${groupRows.length} groups`
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
          </div>
          <AdminTable
            label="Group directory"
            rows={filtered}
            fields={['name', 'provider_slug', 'member_count', 'enabled']}
            labels={labels}
            tone="groups"
            actions={(row) => (
              <Group gap="xs" wrap="nowrap">
                <ActionButton
                  intent="secondary"
                  leftSection={<IconUserPlus size={14} />}
                  onClick={() => setSelectedGroup(row)}
                >
                  Manage members
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
  const [createOpened, setCreateOpened] = useState(false);
  const [selectedUser, setSelectedUser] = useState<Row | null>(null);
  const [roleUser, setRoleUser] = useState<Row | null>(null);
  const active = snapshot.users.filter((row) => Boolean(row.enabled)).length;
  const userRows = snapshot.users.map((user) => ({
    ...user,
    group_names: snapshot.memberships
      .filter((membership) => String(membership.user_id) === String(user.id))
      .map((membership) => labels[String(membership.group_id)] ?? 'Unknown Group'),
    group_count: snapshot.memberships.filter(
      (membership) => String(membership.user_id) === String(user.id),
    ).length,
  }));
  const filtered = filterRows(userRows, query, ['display_name', 'email', 'role', 'group_names']);
  const usersWithGroups = new Set(snapshot.memberships.map((row) => String(row.user_id))).size;
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
                  query ? `${filtered.length} of ${userRows.length}` : `${userRows.length} users`
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
          </div>
          <AdminTable
            label="User directory"
            rows={filtered}
            fields={['display_name', 'email', 'role', 'group_count', 'enabled']}
            labels={labels}
            tone="users"
            actions={(row) => (
              <Group gap="xs" wrap="nowrap">
                <ActionButton
                  intent="secondary"
                  leftSection={<IconBuildingCommunity size={14} />}
                  onClick={() => setSelectedUser(row)}
                >
                  Manage Groups
                </ActionButton>
                <ActionButton
                  intent="secondary"
                  leftSection={<IconEdit size={14} />}
                  onClick={() => setRoleUser(row)}
                >
                  Change role
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
  const policyGrants =
    snapshot.policy_delegations.length + snapshot.direct_user_policy_grants.length;
  const objectTypes = new Map(
    snapshot.objects.map((object) => [String(object.id), primitiveString(object.object_type)]),
  );
  const objectUseRows = (types: string[]) =>
    snapshot.object_use_grants.filter((grant) =>
      types.includes(objectTypes.get(String(grant.object_id)) ?? ''),
    );
  const networkObjectGrants = objectUseRows(['NETWORK', 'NETWORK_GROUP']);
  const portObjectGrants = objectUseRows(['PORT_SERVICE', 'PORT_SERVICE_GROUP']);
  const urlObjectGrants = objectUseRows(['URL', 'URL_GROUP']);
  const applicationObjectGrants = objectUseRows(['APPLICATION', 'APPLICATION_FILTER']);
  const boundaryGrants = snapshot.zone_grants.length + snapshot.ip_range_grants.length;
  const creationAndMappings =
    snapshot.object_create_grants.length + snapshot.category_mappings.length;
  return (
    <Stack gap="lg">
      <Alert color="blue" title="Immediate authorization changes">
        Grant updates apply on the next server-authorized request. They never enable real-provider
        writes or bypass ChangeSet controls.
      </Alert>
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <MetricCard
          label="Policy assignments"
          value={policyGrants}
          detail="Group and direct User access"
          icon={<IconShieldLock size={19} />}
        />
        <MetricCard
          label="Object permissions"
          value={snapshot.object_use_grants.length}
          detail="Network, port, URL, and application access"
          icon={<IconKey size={19} />}
        />
        <MetricCard
          label="Network boundaries"
          value={boundaryGrants}
          detail="Security zones and authorized ranges"
          icon={<IconLink size={19} />}
        />
        <MetricCard
          label="Creation & mappings"
          value={creationAndMappings}
          detail="Creation rights and ownership mappings"
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
              <Tabs.Tab value="mappings">Category mappings</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="policy" pt="lg">
              <GrantTableSection
                title="Group policy delegations"
                rows={snapshot.policy_delegations}
                fields={['group_id', 'policy_id', 'capabilities']}
                resource="policy-delegations"
                labels={labels}
                query={grantQuery}
                sort={grantSort}
                addLabel="Add group delegation"
                onAdd={() => setEditor({ kind: 'policy-delegations' })}
                onRevoke={onRevoke}
                onEdit={(kind, row) => setEditor({ kind, row })}
              />
              <GrantTableSection
                title="Direct User policy grants"
                rows={snapshot.direct_user_policy_grants}
                fields={['user_id', 'group_id', 'policy_id', 'capabilities']}
                resource="direct-user-policy-grants"
                labels={labels}
                query={grantQuery}
                sort={grantSort}
                addLabel="Add User policy grant"
                onAdd={() => setEditor({ kind: 'direct-user-policy-grants' })}
                onRevoke={onRevoke}
                onEdit={(kind, row) => setEditor({ kind, row })}
              />
            </Tabs.Panel>
            <Tabs.Panel value="resources" pt="lg">
              <Tabs defaultValue="network-objects" className="fm-resource-grant-tabs">
                <Tabs.List>
                  <Tabs.Tab value="network-objects">Networks</Tabs.Tab>
                  <Tabs.Tab value="port-objects">Ports</Tabs.Tab>
                  <Tabs.Tab value="url-objects">URLs</Tabs.Tab>
                  <Tabs.Tab value="application-objects">Applications</Tabs.Tab>
                  <Tabs.Tab value="security-zones">Zones</Tabs.Tab>
                  <Tabs.Tab value="ip-ranges">IP ranges</Tabs.Tab>
                  <Tabs.Tab value="object-creation">Creation</Tabs.Tab>
                </Tabs.List>
                <Tabs.Panel value="network-objects" pt="lg">
                  <GrantTableSection
                    title="Network objects"
                    rows={networkObjectGrants}
                    fields={['group_id', 'policy_id', 'object_id', 'permission']}
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
                    fields={['group_id', 'policy_id', 'object_id', 'permission']}
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
                    fields={['group_id', 'policy_id', 'object_id', 'permission']}
                    resource="object-use-grants"
                    labels={labels}
                    query={grantQuery}
                    sort={grantSort}
                    addLabel="Add URL object access"
                    onAdd={() => setEditor({ kind: 'object-use-grants', objectTypes: ['URL'] })}
                    onRevoke={onRevoke}
                    onEdit={(kind, row) => setEditor({ kind, row })}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="application-objects" pt="lg">
                  <GrantTableSection
                    title="Application objects"
                    rows={applicationObjectGrants}
                    fields={['group_id', 'policy_id', 'object_id', 'permission']}
                    resource="object-use-grants"
                    labels={labels}
                    query={grantQuery}
                    sort={grantSort}
                    addLabel="Add application object access"
                    onAdd={() =>
                      setEditor({
                        kind: 'object-use-grants',
                        objectTypes: ['APPLICATION', 'APPLICATION_FILTER'],
                      })
                    }
                    onRevoke={onRevoke}
                    onEdit={(kind, row) => setEditor({ kind, row })}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="security-zones" pt="lg">
                  <GrantTableSection
                    title="Security zones"
                    rows={snapshot.zone_grants}
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
                    rows={snapshot.ip_range_grants}
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
                    rows={snapshot.object_create_grants}
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
            <Tabs.Panel value="mappings" pt="lg">
              <GrantTableSection
                title="Provider category mappings"
                rows={snapshot.category_mappings}
                fields={[
                  'group_id',
                  'policy_id',
                  'category_id',
                  'expected_category_name',
                  'sync_state',
                ]}
                resource="category-mappings"
                labels={labels}
                query={grantQuery}
                sort={grantSort}
                addLabel="Add category mapping"
                onAdd={() => setEditor({ kind: 'category-mappings' })}
                onRevoke={onRevoke}
                onEdit={(kind, row) => setEditor({ kind, row })}
              />
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
  const [role, setRole] = useState<string | null>('viewer');
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    setFeedback(null);
    setSaving(true);
    const payload = isUser
      ? {
          display_name: primary.trim(),
          email: secondary.trim(),
          identity_issuer: 'urn:firewall-manager:development',
          identity_subject: secondary.trim(),
          role: role ?? 'viewer',
        }
      : { name: primary.trim(), provider_slug: secondary.trim().toUpperCase() };
    try {
      await createAdministrativeResource(resource, payload);
      await onSaved();
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
            : 'Create a stable ownership boundary for provider naming and policy delegation.'}
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
              ? 'Used as the development identity subject.'
              : 'Uppercase prefix used for provider-owned names; cannot be changed casually.'
          }
          placeholder={isUser ? 'jordan@example.com' : 'NETENG'}
          value={secondary}
          onChange={(event) => setSecondary(event.currentTarget.value)}
        />
        {isUser && (
          <Select
            label="Application role"
            description="Resource access is still controlled by memberships and grants."
            value={role}
            onChange={setRole}
            data={roleOptions}
            allowDeselect={false}
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
    user ? primitiveString(user.role) : 'viewer',
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
            description="The role controls platform-level actions. Group memberships and access grants remain separate."
            value={role}
            onChange={setRole}
            data={roleOptions}
            allowDeselect={false}
          />
          <Alert color="blue">
            Platform administrators can manage identities, grants, and provider connections.
            Firewall and Group administrators have narrower operational authority.
          </Alert>
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
          <ThemeIcon variant="light" color="gray" size="lg">
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
                : 'Members can select this Group when working with delegated policies.'}
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
  ['policy-delegations', 'Group policy delegation'],
  ['direct-user-policy-grants', 'Direct User policy grant'],
  ['object-use-grants', 'Object access'],
  ['zone-grants', 'Security zone'],
  ['ip-range-grants', 'IP range'],
  ['object-create-grants', 'Object creation'],
  ['category-mappings', 'Provider category mapping'],
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
  const [userId, setUserId] = useState<string | null>(nullableString(initial.row?.user_id));
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
    return options(filteredResources, 'name');
  }, [snapshot, kind, policyId, initial.objectTypes]);
  const resourceRequired = ['object-use-grants', 'zone-grants', 'category-mappings'].includes(kind);
  const directUser = kind === 'direct-user-policy-grants';
  const capabilityGrant = kind === 'policy-delegations' || directUser;
  const editing = Boolean(initial.row);
  const mutableGrant = grantIsMutable(kind);
  const valueRequired = ['ip-range-grants', 'object-create-grants', 'category-mappings'].includes(
    kind,
  );
  const canSubmit =
    Boolean(groupId && policyId) &&
    (!directUser || Boolean(userId)) &&
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
    if (directUser) payload.user_id = userId;
    if (capabilityGrant) {
      payload.capabilities = capabilities;
      payload.is_active = true;
    } else if (kind === 'object-use-grants') {
      payload.object_id = resourceId;
      payload.permission = value || 'use';
    } else if (kind === 'zone-grants') {
      payload.zone_id = resourceId;
      payload.direction = value || 'BOTH';
    } else if (kind === 'ip-range-grants') payload.network = value.trim();
    else if (kind === 'object-create-grants') payload.object_type = value;
    else if (kind === 'category-mappings') {
      payload.category_id = resourceId;
      payload.expected_category_name = value.trim();
      payload.sync_state = 'PENDING';
    }
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
      <Group justify="space-between" align="start" mb="md">
        <Text size="sm" c="dimmed" maw={620}>
          Select a subject, policy boundary, and the exact permission to grant. Existing records
          retain their logical scope while their permission details are updated.
        </Text>
        <AppStatusBadge value="ACTIVE" label="Server enforced" />
      </Group>
      <div className="fm-form-section">
        <Text className="fm-form-section-label">1 · Grant type</Text>
        <Select
          label="Authorization record"
          value={kind}
          onChange={(selected) => {
            setKind(selected ?? 'policy-delegations');
            setUserId(null);
            resetDependentFields();
          }}
          data={grantKinds.map(([itemValue, label]) => ({ value: itemValue, label }))}
          allowDeselect={false}
          disabled
        />
      </div>
      <div className="fm-form-section">
        <Text className="fm-form-section-label">2 · Subject and scope</Text>
        <SimpleGrid cols={{ base: 1, md: directUser ? 3 : 2 }}>
          {directUser && (
            <Select
              searchable
              label="User"
              placeholder="Choose a user"
              value={userId}
              onChange={setUserId}
              data={options(snapshot.users, 'display_name')}
              disabled={editing}
            />
          )}
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
            disabled={editing && kind !== 'category-mappings'}
          />
        )}
        {kind === 'object-use-grants' && (
          <Select
            label="Object permission"
            description="Read permits inspection only. Use permits referencing the object in policy rules and ChangeSets; Read does not imply Use."
            value={value || 'use'}
            onChange={(selected) => setValue(selected ?? 'use')}
            data={[
              { value: 'read', label: 'Read only' },
              { value: 'use', label: 'Use in policy rules' },
            ]}
            allowDeselect={false}
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
            disabled={editing}
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
            placeholder="Choose an object type"
            value={value || null}
            onChange={(selected) => setValue(selected ?? '')}
            data={[
              { value: 'NETWORK', label: 'Network' },
              { value: 'PORT_SERVICE', label: 'Port service' },
              { value: 'URL', label: 'URL' },
              { value: 'APPLICATION', label: 'Application' },
              { value: 'APPLICATION_FILTER', label: 'Application filter' },
            ]}
            disabled={editing}
          />
        )}
        {kind === 'category-mappings' && (
          <TextInput
            label="Expected provider category name"
            description="Must match the provider-side ownership category exactly."
            placeholder="FINANCE__RULES"
            value={value}
            onChange={(event) => setValue(event.currentTarget.value)}
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
  const normalizedQuery = query.trim().toLowerCase();
  const visibleRows = [...rows]
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
                  ? `${visibleRows.length} of ${rows.length}`
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
  { value: 'viewer', label: 'Viewer' },
  { value: 'editor', label: 'Editor' },
  { value: 'approver', label: 'Approver' },
  { value: 'group_admin', label: 'Group administrator' },
  { value: 'firewall_admin', label: 'Firewall administrator' },
  { value: 'admin', label: 'Platform administrator' },
];

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
  if (kind === 'category-mappings') return nullableString(row?.category_id);
  return null;
}

function initialGrantValue(kind: string, row?: Row) {
  if (kind === 'object-use-grants') return primitiveString(row?.permission, 'use');
  if (kind === 'zone-grants') return primitiveString(row?.direction, 'BOTH');
  if (kind === 'ip-range-grants') return primitiveString(row?.network);
  if (kind === 'object-create-grants') return primitiveString(row?.object_type);
  if (kind === 'category-mappings') return primitiveString(row?.expected_category_name);
  return '';
}

function resourceLabel(kind: string) {
  if (kind === 'object-use-grants') return 'Firewall object';
  if (kind === 'zone-grants') return 'Security zone';
  return 'Provider category';
}

function grantIsMutable(kind: string) {
  return ['policy-delegations', 'direct-user-policy-grants', 'category-mappings'].includes(kind);
}

function grantAddTitle(editor: GrantEditor | null) {
  if (!editor) return 'Add access grant';
  if (editor.objectTypes?.includes('NETWORK')) return 'Add network object access';
  if (editor.objectTypes?.includes('PORT_SERVICE')) return 'Add port object access';
  if (editor.objectTypes?.includes('URL')) return 'Add URL object access';
  if (editor.objectTypes?.includes('APPLICATION')) return 'Add application object access';
  const titles: Record<string, string> = {
    'policy-delegations': 'Add group policy delegation',
    'direct-user-policy-grants': 'Add User policy grant',
    'zone-grants': 'Add security zone access',
    'ip-range-grants': 'Add authorized IP range',
    'object-create-grants': 'Add object creation right',
    'category-mappings': 'Add category mapping',
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
