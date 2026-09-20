import { useCallback, useEffect, useState } from 'react';

import {
  ApiError,
  createAdministrativeResource,
  loadAdministration,
  revokeAuthorizationResource,
  updateAdministrativeEnabled,
  upsertAuthorizationResource,
  type AdministrationSnapshot,
} from '../../api/client';
import {
  AppAlert as Alert,
  AppButton as Button,
  AppCard as Card,
  AppErrorState,
  AppLoadingState,
  AppSelect as Select,
  AppSimpleGrid as SimpleGrid,
  AppStack as Stack,
  AppTable as Table,
  AppText as Text,
  AppTextInput as TextInput,
  AppTitle as Title,
} from '../../ui';
import { Tabs } from '../../ui/tabs';
import { authorizationExpectedRevision, providerResourcesForPolicy } from './authorizationRevision';

type State =
  | { status: 'loading' }
  | { status: 'ready'; snapshot: AdministrationSnapshot; message?: string }
  | { status: 'error'; message: string; correlationId?: string };

export function AdministrationPanel() {
  const [state, setState] = useState<State>({ status: 'loading' });
  const refresh = useCallback(
    () =>
      loadAdministration()
        .then((snapshot) => setState({ status: 'ready', snapshot }))
        .catch((error: unknown) => setState(toError(error))),
    [],
  );
  const load = useCallback(() => {
    void refresh();
  }, [refresh]);
  useEffect(load, [load]);
  const revoke = useCallback(
    (resource: string, row: Record<string, unknown>) => {
      const id = String(row.id);
      const revision = Number(row.revision);
      if (!window.confirm('Revoke this authorization record? This takes effect immediately.'))
        return;
      void revokeAuthorizationResource(resource, id, revision)
        .then(refresh)
        .catch((error: unknown) => setState(toError(error)));
    },
    [refresh],
  );
  const toggleEnabled = useCallback(
    (resource: 'users' | 'groups', row: Record<string, unknown>) => {
      const enabled = Boolean(row.enabled);
      const verb = enabled ? 'Disable' : 'Enable';
      if (!window.confirm(`${verb} this ${resource.slice(0, -1)}?`)) return;
      void updateAdministrativeEnabled(resource, String(row.id), !enabled, Number(row.revision))
        .then(refresh)
        .catch((error: unknown) => setState(toError(error)));
    },
    [refresh],
  );

  if (state.status === 'loading')
    return <AppLoadingState label="Loading authorization administration" />;
  if (state.status === 'error') {
    return <AppErrorState message={state.message} reference={state.correlationId} />;
  }
  return (
    <section aria-labelledby="administration-heading">
      <Title id="administration-heading" order={3} mb="sm">
        Authorization administration
      </Title>
      <Alert color="blue" mb="md">
        Grant changes take effect on the next server-authorized request. Provider writes remain
        disabled.
      </Alert>
      <Tabs defaultValue="identities">
        <Tabs.List>
          <Tabs.Tab value="identities">Users and Groups</Tabs.Tab>
          <Tabs.Tab value="grants">Delegations and grants</Tabs.Tab>
          <Tabs.Tab value="mappings">Category mappings</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="identities" pt="md">
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <CreateIdentityForm resource="users" onSaved={refresh} />
            <CreateIdentityForm resource="groups" onSaved={refresh} />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, md: 2 }} mt="md">
            <AdminTable
              title="Users"
              rows={state.snapshot.users}
              fields={['display_name', 'email', 'role', 'enabled']}
              actionLabel={(row) => (row.enabled ? 'Disable' : 'Enable')}
              onAction={(row) => toggleEnabled('users', row)}
            />
            <AdminTable
              title="Groups"
              rows={state.snapshot.groups}
              fields={['name', 'provider_slug', 'enabled']}
              actionLabel={(row) => (row.enabled ? 'Disable' : 'Enable')}
              onAction={(row) => toggleEnabled('groups', row)}
            />
          </SimpleGrid>
          <AdminTable
            title="Memberships"
            rows={state.snapshot.memberships}
            fields={['user_id', 'group_id', 'status', 'revision']}
            onRevoke={(row) => revoke('memberships', row)}
          />
        </Tabs.Panel>
        <Tabs.Panel value="grants" pt="md">
          <GrantForm snapshot={state.snapshot} onSaved={refresh} />
          <SimpleGrid cols={{ base: 1, md: 2 }} mt="md">
            <AdminTable
              title="Policy delegations"
              rows={state.snapshot.policy_delegations}
              fields={['group_id', 'policy_id', 'capabilities', 'revision']}
              onRevoke={(row) => revoke('policy-delegations', row)}
            />
            <AdminTable
              title="Object USE grants"
              rows={state.snapshot.object_use_grants}
              fields={['group_id', 'policy_id', 'object_id', 'permission']}
              onRevoke={(row) => revoke('object-use-grants', row)}
            />
            <AdminTable
              title="Zone grants"
              rows={state.snapshot.zone_grants}
              fields={['group_id', 'policy_id', 'zone_id', 'direction']}
              onRevoke={(row) => revoke('zone-grants', row)}
            />
            <AdminTable
              title="IP ranges"
              rows={state.snapshot.ip_range_grants}
              fields={['group_id', 'policy_id', 'network']}
              onRevoke={(row) => revoke('ip-range-grants', row)}
            />
            <AdminTable
              title="Object creation"
              rows={state.snapshot.object_create_grants}
              fields={['group_id', 'policy_id', 'object_type']}
              onRevoke={(row) => revoke('object-create-grants', row)}
            />
            <AdminTable
              title="Direct User policy grants"
              rows={state.snapshot.direct_user_policy_grants}
              fields={['user_id', 'group_id', 'policy_id', 'capabilities']}
              onRevoke={(row) => revoke('direct-user-policy-grants', row)}
            />
          </SimpleGrid>
        </Tabs.Panel>
        <Tabs.Panel value="mappings" pt="md">
          <AdminTable
            title="Provider category mappings"
            rows={state.snapshot.category_mappings}
            fields={[
              'group_id',
              'policy_id',
              'category_id',
              'expected_category_name',
              'sync_state',
              'revision',
            ]}
            onRevoke={(row) => revoke('category-mappings', row)}
          />
        </Tabs.Panel>
      </Tabs>
    </section>
  );
}

function CreateIdentityForm({
  resource,
  onSaved,
}: {
  resource: 'users' | 'groups';
  onSaved: () => Promise<void>;
}) {
  const [primary, setPrimary] = useState('');
  const [secondary, setSecondary] = useState('');
  const [error, setError] = useState('');
  const submit = () => {
    setError('');
    const payload =
      resource === 'groups'
        ? { name: primary, provider_slug: secondary }
        : {
            display_name: primary,
            email: secondary,
            identity_issuer: 'urn:firewall-manager:development',
            identity_subject: secondary,
            role: 'viewer',
          };
    void createAdministrativeResource(resource, payload)
      .then(onSaved)
      .catch((caught: unknown) =>
        setError(caught instanceof Error ? caught.message : 'Save failed.'),
      );
  };
  return (
    <Card withBorder>
      <Text fw={700}>Create {resource === 'users' ? 'User' : 'Group'}</Text>
      <TextInput
        mt="sm"
        label={resource === 'users' ? 'Display name' : 'Group name'}
        value={primary}
        onChange={(event) => setPrimary(event.currentTarget.value)}
      />
      <TextInput
        mt="sm"
        label={resource === 'users' ? 'Email' : 'Stable provider prefix'}
        value={secondary}
        onChange={(event) => setSecondary(event.currentTarget.value)}
      />
      {error && (
        <Text c="red" size="sm">
          {error}
        </Text>
      )}
      <Button mt="md" onClick={submit} disabled={!primary || !secondary}>
        Create
      </Button>
    </Card>
  );
}

const grantKinds = [
  ['memberships', 'Membership'],
  ['policy-delegations', 'Policy delegation'],
  ['direct-user-policy-grants', 'Direct User policy grant'],
  ['object-use-grants', 'Object USE grant'],
  ['zone-grants', 'Zone grant'],
  ['ip-range-grants', 'IP range grant'],
  ['object-create-grants', 'Object-create grant'],
  ['category-mappings', 'Provider category mapping'],
] as const;

function GrantForm({
  snapshot,
  onSaved,
}: {
  snapshot: AdministrationSnapshot;
  onSaved: () => Promise<void>;
}) {
  const [kind, setKind] = useState<string>('memberships');
  const [userId, setUserId] = useState<string | null>(null);
  const [groupId, setGroupId] = useState<string | null>(null);
  const [policyId, setPolicyId] = useState<string | null>(null);
  const [resourceId, setResourceId] = useState<string | null>(null);
  const [value, setValue] = useState('');
  const [message, setMessage] = useState('');
  const [saving, setSaving] = useState(false);
  const resourceOptions = options(providerResourcesForPolicy(snapshot, kind, policyId), 'name');
  const resourceRequired = ['object-use-grants', 'zone-grants', 'category-mappings'].includes(kind);
  const policyRequired = kind !== 'memberships';
  const submit = () => {
    setMessage('');
    const payload: Record<string, unknown> = {};
    if (userId && ['memberships', 'direct-user-policy-grants'].includes(kind))
      payload.user_id = userId;
    if (groupId) payload.group_id = groupId;
    if (policyId && kind !== 'memberships') payload.policy_id = policyId;
    if (kind === 'memberships') payload.status = 'ACTIVE';
    if (kind === 'policy-delegations' || kind === 'direct-user-policy-grants') {
      payload.capabilities = value
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
      payload.is_active = true;
    } else if (kind === 'object-use-grants') {
      payload.object_id = resourceId;
      payload.permission = 'use';
    } else if (kind === 'zone-grants') {
      payload.zone_id = resourceId;
      payload.direction = value || 'BOTH';
    } else if (kind === 'ip-range-grants') payload.network = value;
    else if (kind === 'object-create-grants') payload.object_type = value;
    else if (kind === 'category-mappings') {
      payload.category_id = resourceId;
      payload.expected_category_name = value;
      payload.sync_state = 'PENDING';
    }
    const expectedRevision = authorizationExpectedRevision(snapshot, kind, payload);
    if (expectedRevision !== undefined) payload.expected_revision = expectedRevision;
    setSaving(true);
    void upsertAuthorizationResource(kind, payload)
      .then(onSaved)
      .then(() => setMessage('Grant saved.'))
      .catch((caught: unknown) =>
        setMessage(caught instanceof Error ? caught.message : 'Save failed.'),
      )
      .finally(() => setSaving(false));
  };
  return (
    <Card
      withBorder
      component="form"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <Title order={4}>Assign authorization</Title>
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} mt="sm">
        <Select
          label="Grant type"
          value={kind}
          onChange={(selected) => {
            setKind(selected ?? 'memberships');
            setResourceId(null);
          }}
          data={grantKinds.map(([value, label]) => ({ value, label }))}
        />
        {['memberships', 'direct-user-policy-grants'].includes(kind) && (
          <Select
            searchable
            label="User"
            value={userId}
            onChange={setUserId}
            data={options(snapshot.users, 'display_name')}
          />
        )}
        <Select
          searchable
          label="Group"
          value={groupId}
          onChange={setGroupId}
          data={options(snapshot.groups, 'name')}
        />
        {kind !== 'memberships' && (
          <Select
            searchable
            label="Access Policy"
            value={policyId}
            onChange={(selected) => {
              setPolicyId(selected);
              setResourceId(null);
            }}
            data={options(snapshot.policies, 'name')}
          />
        )}
        {resourceOptions.length > 0 && (
          <Select
            searchable
            label="Provider resource"
            value={resourceId}
            onChange={setResourceId}
            data={resourceOptions}
          />
        )}
        {!['memberships', 'object-use-grants'].includes(kind) && (
          <TextInput
            label={valueLabel(kind)}
            value={value}
            onChange={(event) => setValue(event.currentTarget.value)}
          />
        )}
      </SimpleGrid>
      {message && (
        <Text c="red" size="sm">
          {message}
        </Text>
      )}
      <Button
        type="submit"
        mt="md"
        disabled={
          !groupId || (policyRequired && !policyId) || (resourceRequired && !resourceId) || saving
        }
      >
        {saving ? 'Saving grant…' : 'Save grant'}
      </Button>
    </Card>
  );
}

function valueLabel(kind: string) {
  if (kind.includes('policy')) return 'Capabilities (comma-separated)';
  if (kind === 'zone-grants') return 'Direction (SOURCE, DESTINATION, BOTH)';
  if (kind === 'ip-range-grants') return 'IPv4/IPv6 network';
  if (kind === 'object-create-grants') return 'Object type';
  return 'Expected provider category name';
}

function options(rows: Array<Record<string, unknown>>, label: string) {
  return rows.map((row) => ({ value: String(row.id), label: String(row[label] ?? row.id) }));
}

function AdminTable({
  title,
  rows,
  fields,
  onRevoke,
  onAction,
  actionLabel,
}: {
  title: string;
  rows: Array<Record<string, unknown>>;
  fields: string[];
  onRevoke?: (row: Record<string, unknown>) => void;
  onAction?: (row: Record<string, unknown>) => void;
  actionLabel?: (row: Record<string, unknown>) => string;
}) {
  return (
    <Stack gap="xs" mt="md">
      <Title order={4}>{title}</Title>
      <div style={{ overflowX: 'auto' }}>
        <Table withTableBorder striped>
          <Table.Thead>
            <Table.Tr>
              {fields.map((field) => (
                <Table.Th key={field}>{field.replaceAll('_', ' ')}</Table.Th>
              ))}
              {(onRevoke || onAction) && <Table.Th>Actions</Table.Th>}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.length === 0 ? (
              <Table.Tr>
                <Table.Td colSpan={fields.length + (onRevoke || onAction ? 1 : 0)}>
                  No records.
                </Table.Td>
              </Table.Tr>
            ) : (
              rows.map((row) => (
                <Table.Tr key={String(row.id)}>
                  {fields.map((field) => (
                    <Table.Td key={field}>{formatValue(row[field])}</Table.Td>
                  ))}
                  {onRevoke && (
                    <Table.Td>
                      <Button color="red" variant="outline" size="xs" onClick={() => onRevoke(row)}>
                        Revoke
                      </Button>
                    </Table.Td>
                  )}
                  {onAction && (
                    <Table.Td>
                      <Button variant="outline" size="xs" onClick={() => onAction(row)}>
                        {actionLabel?.(row) ?? 'Update'}
                      </Button>
                    </Table.Td>
                  )}
                </Table.Tr>
              ))
            )}
          </Table.Tbody>
        </Table>
      </div>
    </Stack>
  );
}

function formatValue(value: unknown) {
  if (Array.isArray(value)) return value.join(', ');
  if (value === null || value === undefined) return '—';
  if (value !== null && typeof value === 'object') return JSON.stringify(value);
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return value.toString();
  }
  return '—';
}

function toError(error: unknown): State {
  return error instanceof ApiError
    ? { status: 'error', message: error.message, correlationId: error.correlationId }
    : { status: 'error', message: 'Authorization administration is unavailable.' };
}
