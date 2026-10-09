// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
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
  AppActionButton,
  AppCard,
  AppButton,
  AppDataTable,
  AppDialog,
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
  const [query, setQuery] = useState('');
  const [resourcePage, setResourcePage] = useState(1);
  const resourcePageSize = useAdaptivePageSize();
  const [busy, setBusy] = useState<string | null>(null);
  const [selectedResource, setSelectedResource] = useState<SyncRow | null>(null);
  const [refreshedInventory, setRefreshedInventory] = useState<Inventory | null>(null);
  const [syncNotice, setSyncNotice] = useState<{
    connectionId: string;
    tone: 'info' | 'success' | 'error';
    message: string;
  } | null>(null);
  const displayedInventory = refreshedInventory ?? inventory;
  useEffect(() => {
    setResourcePage(1);
  }, [managerFilter, policyFilter, typeFilter, stateFilter, query]);
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
            kind: resourceTypeLabel(item.resource_type),
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
  const visibleResources = allResources.filter((item) => {
    const search = query.trim().toLowerCase();
    const matchesQuery =
      !search ||
      [item.name, item.provider, item.kind, item.value, item.resource_id].some((value) =>
        value?.toLowerCase().includes(search),
      );
    return (
      matchesQuery &&
      (managerFilter === 'ALL' || item.manager_id === managerFilter) &&
      (policyFilter === 'ALL' || item.policy_id === policyFilter) &&
      (typeFilter === 'ALL' || item.kind === typeFilter) &&
      (stateFilter === 'ALL' || item.management_state === stateFilter)
    );
  });
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
        <Group gap="sm" wrap="wrap">
          <TextInput
            className="fm-sync-search"
            aria-label="Search synchronized resources"
            placeholder="Search resources"
            leftSection={<IconSearch size={16} />}
            value={query}
            onChange={(event) => setQuery(event.currentTarget.value)}
          />
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
                    {!['OBSERVED', 'MANAGED'].includes(item.management_state) ? (
                      <>
                        <AppButton
                          size="xs"
                          variant="light"
                          onClick={() => setSelectedResource(item)}
                        >
                          View details
                        </AppButton>
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
      <AppDialog
        opened={selectedResource !== null}
        onClose={() => setSelectedResource(null)}
        title={selectedResource ? `${selectedResource.kind} discrepancy` : 'Discrepancy details'}
        centered
        size="lg"
      >
        {selectedResource && (
          <div>
            <Text size="sm" fw={700} mb={4}>
              {selectedResource.name}
            </Text>
            <Text size="sm" c="dimmed" mb="md">
              {selectedResource.provider ?? 'Provider'} · {selectedResource.kind}
            </Text>
            <Group gap="xs" mb="md">
              <Text size="sm">Current state:</Text>
              <AppStatusBadge value={selectedResource.management_state} />
            </Group>
            <Text size="sm" fw={700} mb={4}>
              What this means
            </Text>
            <Text size="sm" mb="md">
              {explainDiscrepancy(selectedResource)}
            </Text>
            <Group gap="xs" mb="md">
              <Text size="sm" fw={600}>
                Recorded value:
              </Text>
              <Text size="sm">{selectedResource.value ?? 'Not available'}</Text>
            </Group>
            {selectedResource.drift_id && (
              <Group justify="flex-end" mt="xl">
                {selectedResource.connection_id && (
                  <AppButton
                    size="sm"
                    variant="light"
                    loading={busy === selectedResource.connection_id}
                    onClick={() => {
                      if (selectedResource.connection_id)
                        void handleSync(selectedResource.connection_id);
                    }}
                  >
                    Refresh provider
                  </AppButton>
                )}
                {selectedResource.management_state !== 'MISSING' && (
                  <AppButton
                    size="sm"
                    variant="light"
                    loading={busy === selectedResource.id}
                    onClick={() => {
                      if (!selectedResource.drift_id) return;
                      setBusy(selectedResource.drift_id);
                      void acceptProviderState(selectedResource.drift_id).finally(() => {
                        setBusy(null);
                        setSelectedResource(null);
                      });
                    }}
                  >
                    Accept provider state
                  </AppButton>
                )}
                {activeGroupId &&
                  ['DRIFTED', 'MISSING'].includes(selectedResource.management_state) && (
                    <AppButton
                      size="sm"
                      variant="light"
                      loading={busy === `restore-${selectedResource.drift_id}`}
                      onClick={() => {
                        if (!selectedResource.drift_id) return;
                        setBusy(`restore-${selectedResource.drift_id}`);
                        void restoreProviderState(selectedResource.drift_id, activeGroupId).finally(
                          () => {
                            setBusy(null);
                            setSelectedResource(null);
                          },
                        );
                      }}
                    >
                      {selectedResource.management_state === 'MISSING'
                        ? 'Propose recreate'
                        : 'Propose restore'}
                    </AppButton>
                  )}
                <AppButton size="sm" variant="subtle" onClick={() => setSelectedResource(null)}>
                  Close
                </AppButton>
              </Group>
            )}
          </div>
        )}
      </AppDialog>
    </>
  );
}

export function explainDiscrepancy(item: {
  management_state: string;
  kind: string;
  provider?: string;
  previous_snapshot?: Record<string, unknown>;
  observed_snapshot?: Record<string, unknown>;
  details?: Record<string, unknown>;
}) {
  const provider = item.provider ?? 'the provider';
  const resource = item.kind.toLowerCase();
  if (item.management_state === 'MISSING') {
    return `This ${resource} is recorded in the application, but it was not found on ${provider}. Refresh the provider to check again, or propose recreating it on the provider.`;
  }
  if (item.management_state === 'UNMANAGED') {
    return `This ${resource} was found on ${provider}, but the application does not manage it. No application change is required unless you choose to take ownership of it.`;
  }
  if (item.management_state === 'CONFLICT') {
    return `This ${resource} has changed in both the application and ${provider}. Review the details before choosing which version to keep.`;
  }
  const recorded = item.previous_snapshot ?? {};
  const nestedBaseline = recorded.application_snapshot;
  const previous =
    nestedBaseline && typeof nestedBaseline === 'object' && !Array.isArray(nestedBaseline)
      ? (nestedBaseline as Record<string, unknown>)
      : recorded;
  const observed = item.observed_snapshot ?? {};
  const ignoredKeys = new Set([
    'metadata',
    'domain_id',
    'sharing_mode',
    'provider_version',
    'fingerprint',
    'member_object_ids',
  ]);
  const changed = Object.keys(previous).filter(
    (key) =>
      key in observed &&
      !ignoredKeys.has(key) &&
      JSON.stringify(previous[key]) !== JSON.stringify(observed[key]),
  );
  if (changed.length) {
    return `This ${resource} exists in both places, but its ${changed
      .map((key) => humanize(key))
      .join(
        ', ',
      )} do not match. The provider is currently reporting the latest value. Choose Accept provider state to update the application, or Propose restore to submit the application's value back to the provider.`;
  }
  const summary = item.details?.summary;
  return typeof summary === 'string'
    ? summary
    : `This ${resource} does not match the last synchronized state from ${provider}. Review the available actions before making a change.`;
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
      description="Append-oriented authorization, administration, Changeset, and provider activity."
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
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [page, setPage] = useState(1);
  const pageSize = useAdaptivePageSize();
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
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pagedRows = rows.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  useEffect(() => {
    setPage(1);
  }, [query, outcome]);
  useEffect(() => {
    setPage((current) => Math.min(current, pageCount));
  }, [pageCount]);
  return (
    <AppCard>
      <Group justify="space-between" align="end" mb="md">
        <div>
          <Text className="fm-eyebrow">Audit event history</Text>
          <Title order={2} size="h4">
            Security activity
          </Title>
        </div>
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
        <>
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
              {pagedRows.map((event) => (
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
                    <AppActionButton intent="quiet" onClick={() => setSelectedEvent(event)}>
                      View details
                    </AppActionButton>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </AppDataTable>
          <AdaptivePagination
            page={currentPage}
            pageSize={pageSize}
            total={rows.length}
            onPageChange={setPage}
          />
        </>
      )}
      <AppDialog
        opened={selectedEvent !== null}
        onClose={() => setSelectedEvent(null)}
        title={selectedEvent ? humanize(selectedEvent.action) : 'Audit event details'}
        centered
        size="lg"
      >
        {selectedEvent && (
          <div className="fm-audit-details">
            <Text size="sm">
              <strong>Actor:</strong> {selectedEvent.actor}
            </Text>
            <Text size="sm">
              <strong>Action:</strong> {humanize(selectedEvent.action)}
            </Text>
            <Text size="sm">
              <strong>Resource:</strong> {humanize(selectedEvent.resource_type)}
            </Text>
            <Text size="sm">
              <strong>Outcome:</strong> {humanize(selectedEvent.decision)}
            </Text>
            <Text size="sm">
              <strong>Reason code:</strong> {humanize(selectedEvent.reason_code)}
            </Text>
            {typeof selectedEvent.details.reason === 'string' && (
              <Text size="sm">
                <strong>Reason:</strong> {selectedEvent.details.reason}
              </Text>
            )}
            {typeof selectedEvent.details.effective_user_email === 'string' && (
              <Text size="sm">
                <strong>Proxied user:</strong> {selectedEvent.details.effective_user_email}
              </Text>
            )}
            {typeof selectedEvent.details.authorization_revision === 'number' && (
              <Text size="sm">
                Authorization Revision: {selectedEvent.details.authorization_revision}
              </Text>
            )}
            <Text size="sm">
              <strong>Interface:</strong> {humanize(selectedEvent.interface)}
            </Text>
            <Text size="sm">
              <strong>Date:</strong> {formatDate(selectedEvent.occurred_at)}
            </Text>
            {selectedEvent.correlation_id && (
              <Text size="sm" className="fm-code">
                <strong>Correlation:</strong> {selectedEvent.correlation_id}
              </Text>
            )}
            <div>
              <Text size="sm" fw={700} mb={4}>
                Details
              </Text>
              <pre className="fm-audit-details-json">
                {JSON.stringify(auditDetailsForDisplay(selectedEvent.details), null, 2)}
              </pre>
            </div>
          </div>
        )}
      </AppDialog>
    </AppCard>
  );
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

function auditDetailsForDisplay(details: Record<string, unknown>): Record<string, unknown> {
  const safeKeys = new Set([
    'authorization_revision',
    'reason',
    'effective_user_email',
    'provider',
    'provider_version',
    'resource_id',
    'change_set_id',
    'deployment_id',
    'error_code',
    'mode',
  ]);
  return Object.fromEntries(
    Object.entries(details).filter(([key, value]) => safeKeys.has(key) && isDisplayValue(value)),
  );
}

function isDisplayValue(value: unknown): value is string | number | boolean | null {
  return value === null || ['string', 'number', 'boolean'].includes(typeof value);
}

function formatDate(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : 'Never';
}

function humanize(value: string) {
  const objectTypeLabels: Record<string, string> = {
    PORT_SERVICE: 'Port',
    PORT_SERVICE_GROUP: 'Port Group',
  };
  if (objectTypeLabels[value]) return objectTypeLabels[value];
  return value
    .toLowerCase()
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

/**
 * Resource types from synchronization are API/storage names. Keep their
 * presentation aligned with the inventory rows above, which already use
 * concise product labels such as "Rule" and "Object".
 */
export function resourceTypeLabel(value: string) {
  const labels: Record<string, string> = {
    access_rules: 'Rule',
    firewall_objects: 'Object',
    policies: 'Policy',
    rule_categories: 'Rule category',
    security_zones: 'Security zone',
  };
  return labels[value] ?? humanize(value);
}
