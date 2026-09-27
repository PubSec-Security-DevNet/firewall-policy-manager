import { useEffect, useMemo, useState } from 'react';
import { IconArrowsShuffle, IconSearch } from '@tabler/icons-react';

import {
  ApiError,
  acceptProviderState,
  loadAdministration,
  loadInventory,
  requestProviderSync,
  loadSynchronizationDiscrepancies,
  restoreProviderState,
  type AdministrationSnapshot,
  type Inventory,
} from '../../api/client';
import {
  AppCard,
  AppButton,
  AppDataTable,
  AppEmptyState,
  AppErrorState,
  AppGroup as Group,
  AppLoadingState,
  AppPage,
  AppProviderBadge,
  AppSelect as Select,
  AppSimpleGrid as SimpleGrid,
  AppStatusBadge,
  AppTable as Table,
  AppText as Text,
  AppTextInput as TextInput,
  AppTitle as Title,
  MetricCard,
} from '../../ui';
import { AdaptivePagination, useAdaptivePageSize } from '../shared/AdaptivePagination';

type ResourceState = { status: 'loading' } | { status: 'ready'; inventory: Inventory } | ErrorState;
type AuditState =
  | { status: 'loading' }
  | { status: 'ready'; snapshot: AdministrationSnapshot }
  | ErrorState;
type ErrorState = { status: 'error'; message: string; correlationId?: string };

interface AuditEvent {
  id: string;
  actor: string;
  acting_group: string | null;
  policy: string | null;
  action: string;
  resource_type: string;
  decision: string;
  reason_code: string;
  interface: string;
  correlation_id: string | null;
  details: Record<string, unknown>;
  occurred_at: string;
}

export function SyncDriftPage({ activeGroupId }: { activeGroupId?: string } = {}) {
  const [state, setState] = useState<ResourceState>({ status: 'loading' });
  useEffect(() => {
    let active = true;
    void loadInventory()
      .then((inventory) => {
        if (!active) return;
        setState({ status: 'ready', inventory: { ...inventory, discrepancies: [] } });
        void loadSynchronizationDiscrepancies()
          .then((discrepancies) => {
            if (!active) return;
            setState((current) =>
              current.status === 'ready'
                ? { ...current, inventory: { ...current.inventory, discrepancies } }
                : current,
            );
          })
          .catch(() => {
            // Provider inventory remains useful if the discrepancy scan is slow or unavailable.
          });
      })
      .catch((error: unknown) => {
        if (active) setState(toError(error, 'Synchronization inventory is unavailable.'));
      });
    return () => {
      active = false;
    };
  }, []);
  return (
    <AppPage
      eyebrow="Infrastructure"
      title="Sync & drift"
      description="Provider synchronization completeness, discrepancies, and resources requiring operator review."
    >
      {state.status === 'loading' && <AppLoadingState label="Loading synchronization state" />}
      {state.status === 'error' && (
        <AppErrorState message={state.message} reference={state.correlationId} />
      )}
      {state.status === 'ready' && (
        <SyncDriftContent inventory={state.inventory} activeGroupId={activeGroupId} />
      )}
    </AppPage>
  );
}

type SyncRow = {
  id: string;
  resource_id: string;
  drift_id?: string;
  name: string;
  manager_id: string;
  connection_id?: string | null;
  policy_id?: string | null;
  provider?: string;
  kind: string;
  management_state: string;
  value?: string | null;
  details?: Record<string, unknown>;
  previous_snapshot?: Record<string, unknown>;
  observed_snapshot?: Record<string, unknown>;
};

function SyncDriftContent({
  inventory,
  activeGroupId,
}: {
  inventory: Inventory;
  activeGroupId?: string;
}) {
  const [managerFilter, setManagerFilter] = useState('ALL');
  const [policyFilter, setPolicyFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [stateFilter, setStateFilter] = useState('ALL');
  const [resourcePage, setResourcePage] = useState(1);
  const resourcePageSize = useAdaptivePageSize();
  const [busy, setBusy] = useState<string | null>(null);
  const [refreshedInventory, setRefreshedInventory] = useState<Inventory | null>(null);
  const [syncNotice, setSyncNotice] = useState<{
    connectionId: string;
    tone: 'info' | 'success' | 'error';
    message: string;
  } | null>(null);
  const displayedInventory = refreshedInventory ?? inventory;
  const providerByManager = new Map(
    displayedInventory.statuses.map((status) => [
      status.manager_id,
      `${status.provider.toUpperCase()} · ${status.display_name}`,
    ]),
  );

  const refreshLiveInventory = async (): Promise<Inventory> => {
    const [nextInventory, discrepancies] = await Promise.all([
      loadInventory(),
      loadSynchronizationDiscrepancies().catch(() => []),
    ]);
    const next = { ...nextInventory, discrepancies };
    setRefreshedInventory(next);
    return next;
  };

  const handleSync = async (connectionId: string, mode: 'FULL' | 'NON_APPLICATIONS' = 'FULL') => {
    setBusy(connectionId);
    setSyncNotice({
      connectionId,
      tone: 'info',
      message: 'Sync queued. Waiting for the worker to start…',
    });
    try {
      await requestProviderSync(connectionId, mode);
      for (let attempt = 0; attempt < 120; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1000));
        const next = await refreshLiveInventory();
        const status = next.statuses.find((item) => item.connection_id === connectionId);
        if (status?.sync_status === 'COMPLETED') {
          setSyncNotice({
            connectionId,
            tone: 'success',
            message: `Sync completed at ${formatDate(status.last_sync_at)}.`,
          });
          return;
        }
        if (status?.sync_status === 'FAILED' || status?.error_code) {
          setSyncNotice({
            connectionId,
            tone: 'error',
            message: `Sync failed: ${humanize(status.error_code ?? 'PROVIDER_SYNC_FAILED')}.`,
          });
          return;
        }
        setSyncNotice({
          connectionId,
          tone: 'info',
          message:
            status?.sync_status === 'RUNNING'
              ? 'Sync is running. Refreshing provider state…'
              : 'Sync queued. Waiting for the worker to start…',
        });
      }
      setSyncNotice({
        connectionId,
        tone: 'info',
        message: 'Sync is still running. The provider status above will update when it finishes.',
      });
    } catch (error: unknown) {
      setSyncNotice({
        connectionId,
        tone: 'error',
        message:
          error instanceof ApiError
            ? `Sync could not be queued: ${error.message}`
            : 'Sync could not be queued.',
      });
    } finally {
      setBusy(null);
    }
  };
  const allResources: SyncRow[] = Array.from(
    new Map(
      [
        ...displayedInventory.policies.map((item) => ({
          ...item,
          resource_id: item.id,
          provider: providerByManager.get(item.manager_id),
          kind: 'Policy',
        })),
        ...displayedInventory.rules.map((item) => ({
          ...item,
          resource_id: item.id,
          provider: providerByManager.get(item.manager_id),
          kind: 'Rule',
        })),
        ...displayedInventory.objects
          .filter(
            (item) =>
              item.object_type !== 'APPLICATION' && item.object_type !== 'APPLICATION_FILTER',
          )
          .map((item) => ({
            ...item,
            resource_id: item.id,
            provider: providerByManager.get(item.manager_id),
            kind: 'Object',
            value: item.value,
          })),
        ...displayedInventory.discrepancies
          .filter(
            (item) =>
              item.resource_type !== 'firewall_objects' ||
              !(
                typeof item.observed_snapshot.object_type === 'string' &&
                ['APPLICATION', 'APPLICATION_FILTER'].includes(item.observed_snapshot.object_type)
              ),
          )
          .map((item) => ({
            id: item.id,
            resource_id: item.resource_id,
            drift_id: item.id,
            name: item.name,
            manager_id: item.manager_id,
            connection_id: item.connection_id,
            provider: providerByManager.get(item.manager_id) ?? item.provider.toUpperCase(),
            policy_id: item.policy_id,
            kind: item.resource_type,
            management_state: item.provider_only ? 'UNMANAGED' : item.state,
            value:
              typeof item.observed_snapshot.normalized_value === 'string'
                ? item.observed_snapshot.normalized_value
                : null,
            details: item.details,
            previous_snapshot: item.previous_snapshot,
            observed_snapshot: item.observed_snapshot,
          })),
      ].map((item) => [item.resource_id, item] as const),
    ).values(),
  );
  const visibleResources = allResources.filter(
    (item) =>
      (managerFilter === 'ALL' || item.manager_id === managerFilter) &&
      (policyFilter === 'ALL' || item.policy_id === policyFilter) &&
      (typeFilter === 'ALL' || item.kind === typeFilter) &&
      (stateFilter === 'ALL' || item.management_state === stateFilter),
  );
  const resourcePageCount = Math.max(1, Math.ceil(visibleResources.length / resourcePageSize));
  const currentResourcePage = Math.min(resourcePage, resourcePageCount);
  const pagedResources = visibleResources.slice(
    (currentResourcePage - 1) * resourcePageSize,
    currentResourcePage * resourcePageSize,
  );
  const discrepancies = visibleResources.filter(
    (item) => !['OBSERVED', 'MANAGED'].includes(item.management_state),
  );
  const failures = displayedInventory.statuses.filter(
    (item) => item.error_code || !item.sync_complete || item.sync_status === 'FAILED',
  );
  return (
    <>
      <SimpleGrid cols={{ base: 1, sm: 3 }}>
        <MetricCard
          label="Reporting providers"
          value={displayedInventory.statuses.length}
          detail="Organization-scoped managers"
          icon={<IconArrowsShuffle size={18} />}
        />
        <MetricCard
          label="Sync failures"
          value={failures.length}
          detail={failures.length ? 'Operator attention required' : 'No active failures'}
        />
        <MetricCard
          label="Discrepancies"
          value={discrepancies.length}
          detail="Missing, drifted, unmanaged, or conflicting resources"
        />
      </SimpleGrid>
      <AppCard>
        <Group gap="sm" wrap="wrap">
          <Select
            className="fm-sync-filter"
            aria-label="Filter provider connection"
            value={managerFilter}
            onChange={(value) => setManagerFilter(value ?? 'ALL')}
            data={[
              { value: 'ALL', label: 'All provider connections' },
              ...displayedInventory.statuses.map((item) => ({
                value: item.manager_id,
                label: `${item.provider.toUpperCase()} · ${item.display_name}`,
              })),
            ]}
          />
          <Select
            className="fm-sync-filter"
            aria-label="Filter policy"
            value={policyFilter}
            onChange={(value) => setPolicyFilter(value ?? 'ALL')}
            data={[
              { value: 'ALL', label: 'All policies' },
              ...displayedInventory.policies.map((item) => ({
                value: item.id,
                label: `Policy · ${item.name}`,
              })),
            ]}
          />
          <Select
            className="fm-sync-filter"
            aria-label="Filter resource type"
            value={typeFilter}
            onChange={(value) => setTypeFilter(value ?? 'ALL')}
            data={[
              { value: 'ALL', label: 'All resource types' },
              ...Array.from(new Set(allResources.map((item) => item.kind))).map((value) => ({
                value,
                label: humanize(value),
              })),
            ]}
          />
          <Select
            className="fm-sync-filter"
            aria-label="Filter synchronization state"
            value={stateFilter}
            onChange={(value) => setStateFilter(value ?? 'ALL')}
            data={[
              { value: 'ALL', label: 'All sync states' },
              ...Array.from(new Set(allResources.map((item) => item.management_state))).map(
                (value) => ({ value, label: humanize(value) }),
              ),
            ]}
          />
        </Group>
      </AppCard>
      <AppCard>
        <Group justify="space-between" mb="md">
          <div>
            <Text className="fm-eyebrow">Provider state</Text>
            <Title order={2} size="h4">
              Synchronization health
            </Title>
          </div>
        </Group>
        {syncNotice && (
          <Text
            size="sm"
            c={
              syncNotice.tone === 'error' ? 'red' : syncNotice.tone === 'success' ? 'teal' : 'blue'
            }
            mb="md"
          >
            {syncNotice.message}
          </Text>
        )}
        {displayedInventory.statuses.length === 0 ? (
          <AppEmptyState
            title="No provider status"
            description="Configure and synchronize a provider connection to populate this view."
          />
        ) : (
          <AppDataTable label="Provider synchronization health">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Provider</Table.Th>
                <Table.Th>Manager</Table.Th>
                <Table.Th>Version</Table.Th>
                <Table.Th>Sync state</Table.Th>
                <Table.Th>Resources seen</Table.Th>
                <Table.Th>Last sync</Table.Th>
                <Table.Th>Evidence</Table.Th>
                <Table.Th>Action</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {displayedInventory.statuses.map((status) => (
                <Table.Tr key={status.manager_id}>
                  <Table.Td>
                    <AppProviderBadge provider={status.provider} />
                  </Table.Td>
                  <Table.Td>
                    <Text fw={650}>{status.display_name}</Text>
                    {status.error_code && (
                      <Text size="xs" c="red">
                        {humanize(status.error_code)}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>{status.provider_version ?? 'Not reported'}</Table.Td>
                  <Table.Td>
                    <AppStatusBadge
                      value={status.sync_status}
                      label={status.sync_status ? humanize(status.sync_status) : 'Never synced'}
                    />
                  </Table.Td>
                  <Table.Td>{status.resources_seen}</Table.Td>
                  <Table.Td>{formatDate(status.last_sync_at)}</Table.Td>
                  <Table.Td>{humanize(status.evidence_profile)}</Table.Td>
                  <Table.Td>
                    {status.connection_id && (
                      <Group gap="xs" wrap="wrap">
                        <AppButton
                          size="xs"
                          variant="light"
                          loading={busy === status.connection_id}
                          onClick={() => {
                            const connectionId = status.connection_id;
                            if (!connectionId) return;
                            void handleSync(connectionId, 'FULL');
                          }}
                        >
                          Sync all
                        </AppButton>
                        <AppButton
                          size="xs"
                          variant="light"
                          loading={busy === status.connection_id}
                          onClick={() => {
                            const connectionId = status.connection_id;
                            if (!connectionId) return;
                            void handleSync(connectionId, 'NON_APPLICATIONS');
                          }}
                        >
                          Sync without applications
                        </AppButton>
                      </Group>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </AppDataTable>
        )}
      </AppCard>
      <AppCard>
        <Text className="fm-eyebrow">Reconciliation queue</Text>
        <Title order={2} size="h4" mb="md">
          Current resource state
        </Title>
        {visibleResources.length === 0 ? (
          <AppEmptyState
            title="No resources match these filters"
            description="Change the filters to view synchronized or discrepant resources."
          />
        ) : (
          <AppDataTable label="Current provider resource state">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Resource</Table.Th>
                <Table.Th>Provider</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th>Current value</Table.Th>
                <Table.Th>Current state</Table.Th>
                <Table.Th>Required action</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {pagedResources.map((item) => (
                <Table.Tr key={`${item.kind}-${item.resource_id}`}>
                  <Table.Td>{item.name}</Table.Td>
                  <Table.Td>{item.provider ?? '—'}</Table.Td>
                  <Table.Td>{item.kind}</Table.Td>
                  <Table.Td>{item.value ?? '—'}</Table.Td>
                  <Table.Td>
                    <AppStatusBadge value={item.management_state} />
                  </Table.Td>
                  <Table.Td>
                    {!['OBSERVED', 'MANAGED', 'UNMANAGED'].includes(item.management_state) ? (
                      <>
                        <details>
                          <summary>Review provider state</summary>
                          <Text size="xs" mt="xs">
                            {differenceSummary(item)}
                          </Text>
                        </details>
                        {item.drift_id && (
                          <Group gap="xs" mt="xs">
                            {item.connection_id && (
                              <AppButton
                                size="xs"
                                variant="subtle"
                                loading={busy === item.connection_id}
                                onClick={() => {
                                  if (item.connection_id) void handleSync(item.connection_id);
                                }}
                              >
                                Refresh from provider
                              </AppButton>
                            )}
                            {item.management_state !== 'MISSING' && (
                              <AppButton
                                size="xs"
                                variant="subtle"
                                loading={busy === item.id}
                                onClick={() => {
                                  if (!item.drift_id) return;
                                  setBusy(item.drift_id);
                                  void acceptProviderState(item.drift_id).finally(() =>
                                    setBusy(null),
                                  );
                                }}
                              >
                                Accept provider state
                              </AppButton>
                            )}
                            {activeGroupId &&
                              ['DRIFTED', 'MISSING'].includes(item.management_state) && (
                                <AppButton
                                  size="xs"
                                  variant="subtle"
                                  loading={busy === `restore-${item.drift_id}`}
                                  onClick={() => {
                                    if (!item.drift_id) return;
                                    setBusy(`restore-${item.drift_id}`);
                                    void restoreProviderState(item.drift_id, activeGroupId).finally(
                                      () => setBusy(null),
                                    );
                                  }}
                                >
                                  {item.management_state === 'MISSING'
                                    ? 'Propose recreate'
                                    : 'Propose restore'}
                                </AppButton>
                              )}
                          </Group>
                        )}
                      </>
                    ) : (
                      <Text size="sm" c="dimmed">
                        {item.management_state === 'UNMANAGED'
                          ? 'Provider-only resource'
                          : 'Current provider state is synchronized'}
                      </Text>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </AppDataTable>
        )}
        <AdaptivePagination
          page={currentResourcePage}
          pageSize={resourcePageSize}
          total={visibleResources.length}
          onPageChange={setResourcePage}
        />
      </AppCard>
    </>
  );
}

function differenceSummary(item: {
  previous_snapshot?: Record<string, unknown>;
  observed_snapshot?: Record<string, unknown>;
  details?: Record<string, unknown>;
}) {
  const previous = item.previous_snapshot ?? {};
  const observed = item.observed_snapshot ?? {};
  const changed = Object.keys({ ...previous, ...observed }).filter(
    (key) => JSON.stringify(previous[key]) !== JSON.stringify(observed[key]),
  );
  if (changed.length) {
    return `${changed
      .map(
        (key) =>
          `${key}: ${formatSnapshotValue(previous[key])} → ${formatSnapshotValue(observed[key])}`,
      )
      .join(' · ')}. Provider state is current; restore requires a new ChangeSet.`;
  }
  const summary = item.details?.summary;
  return typeof summary === 'string'
    ? summary
    : 'Provider state differs from the last synchronized snapshot.';
}

function formatSnapshotValue(value: unknown) {
  if (value === undefined) return 'not set';
  if (value === null) return 'none';
  if (typeof value === 'string') return value || 'empty';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

export function AuditPage() {
  const [state, setState] = useState<AuditState>({ status: 'loading' });
  useEffect(() => {
    let active = true;
    void loadAdministration()
      .then((snapshot) => {
        if (active) setState({ status: 'ready', snapshot });
      })
      .catch((error: unknown) => {
        if (active) setState(toError(error, 'Audit evidence is unavailable.'));
      });
    return () => {
      active = false;
    };
  }, []);
  return (
    <AppPage
      eyebrow="Operations"
      title="Audit"
      description="Append-oriented authorization, administration, ChangeSet, and provider activity."
    >
      {state.status === 'loading' && <AppLoadingState label="Loading audit evidence" />}
      {state.status === 'error' && (
        <AppErrorState message={state.message} reference={state.correlationId} />
      )}
      {state.status === 'ready' && <AuditContent snapshot={state.snapshot} />}
    </AppPage>
  );
}

function AuditContent({ snapshot }: { snapshot: AdministrationSnapshot }) {
  const events = useMemo(
    () => (snapshot.audit_events ?? []).filter(isAuditEvent),
    [snapshot.audit_events],
  );
  const [query, setQuery] = useState('');
  const [outcome, setOutcome] = useState<string | null>('ALL');
  const rows = useMemo(
    () =>
      events.filter((event) => {
        const search = query.toLowerCase();
        const matchesQuery = [
          event.actor,
          event.acting_group,
          event.policy,
          event.action,
          event.resource_type,
          event.reason_code,
        ].some((value) => value?.toLowerCase().includes(search));
        return matchesQuery && (outcome === 'ALL' || event.decision === outcome);
      }),
    [events, outcome, query],
  );
  return (
    <AppCard>
      <Group justify="space-between" align="end" mb="md">
        <div>
          <Text className="fm-eyebrow">Latest 200 events</Text>
          <Title order={2} size="h4">
            Security activity
          </Title>
        </div>
        <AppStatusBadge value="READ_ONLY" label="Append-oriented evidence" />
      </Group>
      <Group mb="md">
        <TextInput
          aria-label="Search audit events"
          placeholder="Actor, Group, policy, action, resource…"
          leftSection={<IconSearch size={15} />}
          value={query}
          onChange={(event) => setQuery(event.currentTarget.value)}
          w={{ base: '100%', sm: 360 }}
        />
        <Select
          aria-label="Filter audit outcome"
          value={outcome}
          onChange={setOutcome}
          data={[
            { value: 'ALL', label: 'All outcomes' },
            { value: 'ALLOW', label: 'Allowed' },
            { value: 'DENY', label: 'Denied' },
            { value: 'SUCCESS', label: 'Succeeded' },
            { value: 'FAILED', label: 'Failed' },
          ]}
        />
      </Group>
      {rows.length === 0 ? (
        <AppEmptyState
          title={events.length ? 'No matching audit events' : 'No audit activity recorded'}
          description={
            events.length
              ? 'Adjust the current search or outcome filter.'
              : 'Privileged activity and authorization denials will appear here.'
          }
        />
      ) : (
        <AppDataTable label="Audit event history">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Date / time</Table.Th>
              <Table.Th>Actor</Table.Th>
              <Table.Th>Acting Group</Table.Th>
              <Table.Th>Policy</Table.Th>
              <Table.Th>Action</Table.Th>
              <Table.Th>Resource</Table.Th>
              <Table.Th>Outcome</Table.Th>
              <Table.Th>Details</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((event) => (
              <Table.Tr key={event.id}>
                <Table.Td>{formatDate(event.occurred_at)}</Table.Td>
                <Table.Td>{event.actor}</Table.Td>
                <Table.Td>{event.acting_group ?? 'Organization'}</Table.Td>
                <Table.Td>{event.policy ?? 'Not policy-scoped'}</Table.Td>
                <Table.Td>{humanize(event.action)}</Table.Td>
                <Table.Td>{humanize(event.resource_type)}</Table.Td>
                <Table.Td>
                  <AppStatusBadge value={event.decision} />
                </Table.Td>
                <Table.Td>
                  <details>
                    <summary>View details</summary>
                    <Text size="xs" mt="xs">
                      {humanize(event.reason_code)} · {humanize(event.interface)}
                    </Text>
                    {event.correlation_id && (
                      <Text size="10px" c="dimmed" className="fm-code" mt={4}>
                        Correlation: {event.correlation_id}
                      </Text>
                    )}
                    {safeDetailSummary(event.details) && (
                      <Text size="10px" c="dimmed" mt={4}>
                        {safeDetailSummary(event.details)}
                      </Text>
                    )}
                  </details>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </AppDataTable>
      )}
    </AppCard>
  );
}

function safeDetailSummary(details: Record<string, unknown>) {
  const allowed = ['authorization_revision', 'status', 'error_code', 'operation', 'provider'];
  return allowed
    .filter((key) => details[key] !== undefined)
    .map((key) => `${humanize(key)}: ${String(details[key])}`)
    .join(' · ');
}

function toError(error: unknown, fallback: string): ErrorState {
  return error instanceof ApiError
    ? { status: 'error', message: error.message, correlationId: error.correlationId }
    : { status: 'error', message: fallback };
}

function isAuditEvent(
  value: Record<string, unknown>,
): value is Record<string, unknown> & AuditEvent {
  return (
    typeof value.id === 'string' &&
    typeof value.actor === 'string' &&
    typeof value.action === 'string' &&
    typeof value.resource_type === 'string' &&
    typeof value.decision === 'string' &&
    typeof value.reason_code === 'string' &&
    typeof value.interface === 'string' &&
    typeof value.occurred_at === 'string' &&
    typeof value.details === 'object' &&
    value.details !== null
  );
}

function formatDate(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : 'Never';
}

function humanize(value: string) {
  return value
    .toLowerCase()
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}
