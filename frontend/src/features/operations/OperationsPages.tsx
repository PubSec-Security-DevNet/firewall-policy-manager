import { useEffect, useMemo, useState } from 'react';
import { IconArrowsShuffle, IconSearch } from '@tabler/icons-react';

import {
  ApiError,
  loadAdministration,
  loadInventory,
  type AdministrationSnapshot,
  type Inventory,
} from '../../api/client';
import {
  AppCard,
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

export function SyncDriftPage() {
  const [state, setState] = useState<ResourceState>({ status: 'loading' });
  useEffect(() => {
    let active = true;
    void loadInventory()
      .then((inventory) => {
        if (active) setState({ status: 'ready', inventory });
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
      {state.status === 'ready' && <SyncDriftContent inventory={state.inventory} />}
    </AppPage>
  );
}

function SyncDriftContent({ inventory }: { inventory: Inventory }) {
  const discrepancies = [
    ...inventory.policies.map((item) => ({ ...item, kind: 'Policy' })),
    ...inventory.rules.map((item) => ({ ...item, kind: 'Rule' })),
    ...inventory.objects.map((item) => ({ ...item, kind: 'Object' })),
  ].filter((item) => !['OBSERVED', 'MANAGED'].includes(item.management_state));
  const failures = inventory.statuses.filter(
    (item) => item.error_code || !item.sync_complete || item.sync_status === 'FAILED',
  );
  return (
    <>
      <SimpleGrid cols={{ base: 1, sm: 3 }}>
        <MetricCard
          label="Reporting providers"
          value={inventory.statuses.length}
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
          detail="Missing, drifted, or conflicting resources"
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
        {inventory.statuses.length === 0 ? (
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
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {inventory.statuses.map((status) => (
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
                </Table.Tr>
              ))}
            </Table.Tbody>
          </AppDataTable>
        )}
      </AppCard>
      <AppCard>
        <Text className="fm-eyebrow">Reconciliation queue</Text>
        <Title order={2} size="h4" mb="md">
          Drift and conflicts
        </Title>
        {discrepancies.length === 0 ? (
          <AppEmptyState
            title="No discrepancies detected"
            description="Synchronized policy, rule, and object records have no missing, drifted, or conflicting state."
          />
        ) : (
          <AppDataTable label="Resources with synchronization discrepancies">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Resource</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th>Current state</Table.Th>
                <Table.Th>Required action</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {discrepancies.map((item) => (
                <Table.Tr key={`${item.kind}-${item.id}`}>
                  <Table.Td>{item.name}</Table.Td>
                  <Table.Td>{item.kind}</Table.Td>
                  <Table.Td>
                    <AppStatusBadge value={item.management_state} />
                  </Table.Td>
                  <Table.Td>Review provider state before creating a new ChangeSet.</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </AppDataTable>
        )}
      </AppCard>
    </>
  );
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
