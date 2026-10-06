import { useEffect, useState } from 'react';
import { IconRocket, IconRefresh, IconSearch } from '@tabler/icons-react';
import {
  ApiError,
  loadDeploymentChangeSets,
  loadDeployments,
  loadProviderConnections,
  retryDeployment,
  rollbackDeployment,
  type ChangeSet,
  type Deployment,
  type ProviderConnection,
} from '../../api/client';
import {
  AppButton,
  AppActionButton,
  AppCard,
  AppCheckbox,
  AppDataTable,
  AppDialog,
  AppEmptyState,
  AppErrorState,
  AppGroup,
  AppLoadingState,
  AppPaper,
  AppPage,
  AppSimpleGrid,
  AppSelect,
  AppStatusBadge,
  AppTable,
  AppText,
  AppTextInput,
  MetricCard,
} from '../../ui';
import { ChangeSetDetails } from '../changesets/ChangeSetPanel';
import { AdaptivePagination, useAdaptivePageSize } from '../shared/AdaptivePagination';

const DEPLOYMENT_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

function formatInterval(minutes: number) {
  if (minutes % 1440 === 0) return `every ${minutes / 1440} day${minutes === 1440 ? '' : 's'}`;
  if (minutes % 60 === 0) return `every ${minutes / 60} hour${minutes === 60 ? '' : 's'}`;
  return `every ${minutes} minute${minutes === 1 ? '' : 's'}`;
}

export function DeploymentsPage({
  onViewChangeSet,
}: {
  onViewChangeSet?: (changeSetId: string) => void;
} = {}) {
  const [items, setItems] = useState<Deployment[] | null>(null);
  const [providerConnections, setProviderConnections] = useState<ProviderConnection[]>([]);
  const [error, setError] = useState<string>();
  const [refreshing, setRefreshing] = useState(false);
  const [retryingId, setRetryingId] = useState<string>();
  const [rollingBackId, setRollingBackId] = useState<string>();
  const [rollbackDialogId, setRollbackDialogId] = useState<string>();
  const [selectedRollbackIds, setSelectedRollbackIds] = useState<string[]>([]);
  const [rollbackChangeSets, setRollbackChangeSets] = useState<ChangeSet[]>([]);
  const [rollbackDetails, setRollbackDetails] = useState<ChangeSet>();
  const [detailsId, setDetailsId] = useState<string>();
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [providerFilter, setProviderFilter] = useState('ALL');
  const [page, setPage] = useState(1);
  const pageSize = useAdaptivePageSize();
  const selected = items?.find((item) => item.id === detailsId);
  const refresh = () => {
    setRefreshing(true);
    void loadDeployments()
      .then(setItems)
      .catch((reason: unknown) =>
        setError(reason instanceof Error ? reason.message : 'Deployments could not be loaded.'),
      )
      .finally(() => setRefreshing(false));
  };
  const retry = (deploymentId: string) => {
    setRetryingId(deploymentId);
    void retryDeployment(deploymentId)
      .then(() => refresh())
      .catch((reason: unknown) =>
        setError(reason instanceof Error ? reason.message : 'Deployment retry failed.'),
      )
      .finally(() => setRetryingId(undefined));
  };
  const openRollbackDialog = (item: Deployment) => {
    setRollbackDialogId(item.id);
    setSelectedRollbackIds(item.included_change_set_ids);
    setRollbackChangeSets([]);
    void loadDeploymentChangeSets(item.id)
      .then(setRollbackChangeSets)
      .catch((reason: unknown) =>
        setError(reason instanceof Error ? reason.message : 'Changesets could not be loaded.'),
      );
  };
  const rollback = (deploymentId: string) => {
    if (selectedRollbackIds.length === 0) return;
    setRollingBackId(deploymentId);
    void rollbackDeployment(deploymentId, selectedRollbackIds)
      .then((changeSets) => {
        setRollbackDialogId(undefined);
        refresh();
        let attempts = 0;
        const queuePoll = window.setInterval(() => {
          refresh();
          attempts += 1;
          if (attempts >= 20) window.clearInterval(queuePoll);
        }, 1_000);
        if (changeSets[0]) onViewChangeSet?.(changeSets[0].id);
      })
      .catch((reason: unknown) => setError(formatRollbackError(reason)))
      .finally(() => setRollingBackId(undefined));
  };
  useEffect(() => {
    const initial = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 5_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, []);
  useEffect(() => {
    void loadProviderConnections()
      .then(setProviderConnections)
      .catch(() => setProviderConnections([]));
  }, []);
  const counts = {
    active:
      items?.filter(
        (item) =>
          ['SCHEDULED', 'READY', 'DEPLOYING'].includes(item.state) ||
          item.rollback_state === 'ROLLING_BACK',
      ).length ?? 0,
    completed: 0,
    failed: 0,
  };
  const deploymentWindowStart = Date.now() - DEPLOYMENT_WINDOW_MS;
  counts.completed =
    items?.filter(
      (item) =>
        item.state === 'DEPLOYED' &&
        item.rollback_state !== 'ROLLED_BACK' &&
        Date.parse(item.updated_at) >= deploymentWindowStart,
    ).length ?? 0;
  counts.failed =
    items?.filter(
      (item) => deploymentHasFailure(item) && Date.parse(item.updated_at) >= deploymentWindowStart,
    ).length ?? 0;
  const visibleItems = (items ?? []).filter((item) => {
    const search = query.trim().toLowerCase();
    const matchesStatus = statusFilter === 'ALL' || deploymentStatusKey(item) === statusFilter;
    const matchesProvider =
      providerFilter === 'ALL' || item.provider_connection_id === providerFilter;
    if (!search) return matchesStatus && matchesProvider;
    const providerMessages = Array.isArray(item.failure_info.provider_messages)
      ? item.failure_info.provider_messages.map((message) => formatProviderMessage(message))
      : [];
    return (
      matchesStatus &&
      matchesProvider &&
      [
        item.id,
        item.state,
        item.rollback_state,
        item.failure_info.code,
        ...providerMessages,
        ...item.included_change_set_ids,
      ].some((value) => typeof value === 'string' && value.toLowerCase().includes(search))
    );
  });
  const pageCount = Math.max(1, Math.ceil(visibleItems.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pagedItems = visibleItems.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  useEffect(() => {
    setPage(1);
  }, [query, statusFilter, providerFilter]);
  useEffect(() => {
    setPage((current) => Math.min(current, pageCount));
  }, [pageCount]);
  return (
    <AppPage
      eyebrow="Operations"
      title="Deployments"
      description="Connector-level deployment batches for staged provider changes. Status refreshes automatically."
    >
      <AppGroup justify="space-between" mb="lg">
        <AppGroup gap="xs">
          <IconRocket size={18} />
          <AppGroup gap="sm" wrap="wrap">
            <AppText size="sm" c="dimmed">
              Automatic deployment schedules:
            </AppText>
            {providerConnections.length > 0 ? (
              providerConnections.map((connection) => (
                <AppStatusBadge
                  key={connection.id}
                  value={connection.deployment_schedule_enabled ? 'ACTIVE' : 'DISABLED'}
                  label={`${connection.display_name}: ${connection.deployment_schedule_enabled ? formatInterval(connection.deployment_interval_minutes) : 'disabled'}`}
                />
              ))
            ) : (
              <AppText size="sm" c="dimmed">
                Provider schedules are unavailable.
              </AppText>
            )}
          </AppGroup>
        </AppGroup>
        <AppButton
          variant="light"
          leftSection={<IconRefresh size={15} />}
          loading={refreshing}
          onClick={refresh}
        >
          Refresh
        </AppButton>
      </AppGroup>
      {error && <AppErrorState message={error} />}
      {!error && !items && <AppLoadingState label="Loading deployments" />}
      {items && (
        <AppSimpleGrid cols={{ base: 1, sm: 3 }} mb="lg">
          <MetricCard
            label="In progress"
            value={counts.active}
            detail="Scheduled, queued, or deploying"
            icon={<IconRocket size={18} />}
          />
          <MetricCard
            label="Succeeded (30 days)"
            value={counts.completed}
            detail="Provider-confirmed deployments"
            icon={<IconRocket size={18} />}
          />
          <MetricCard
            label="Failed (30 days)"
            value={counts.failed}
            detail="Failed or uncertain deployments"
            icon={<IconRocket size={18} />}
          />
        </AppSimpleGrid>
      )}
      {!error && items?.length === 0 && (
        <AppEmptyState
          title="No deployments"
          description="No connector has a queued or completed deployment batch yet."
        />
      )}
      {items && items.length > 0 && (
        <AppCard>
          <AppGroup mb="md">
            <AppTextInput
              aria-label="Search deployments"
              placeholder="Search deployments"
              leftSection={<IconSearch size={15} />}
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
              w={{ base: '100%', sm: 380 }}
            />
            <AppSelect
              aria-label="Filter deployments by status"
              value={statusFilter}
              onChange={(value) => setStatusFilter(value ?? 'ALL')}
              data={[
                { value: 'ALL', label: 'All statuses' },
                ...Array.from(new Set((items ?? []).map(deploymentStatusKey))).map((value) => ({
                  value,
                  label: deploymentStatusLabel(value),
                })),
              ]}
              w={{ base: '100%', sm: 200 }}
            />
            <AppSelect
              aria-label="Filter deployments by provider"
              value={providerFilter}
              onChange={(value) => setProviderFilter(value ?? 'ALL')}
              data={[
                { value: 'ALL', label: 'All providers' },
                ...providerConnections.map((connection) => ({
                  value: connection.id,
                  label: connection.display_name,
                })),
              ]}
              w={{ base: '100%', sm: 220 }}
            />
          </AppGroup>
          {visibleItems.length === 0 ? (
            <AppEmptyState
              title="No deployments match your search"
              description="Try a different batch ID, status, provider message, or Changeset ID."
            />
          ) : (
            <>
              <AppDataTable label="Deployments">
                <AppTable.Thead>
                  <AppTable.Tr>
                    <AppTable.Th>Batch</AppTable.Th>
                    <AppTable.Th>Status</AppTable.Th>
                    <AppTable.Th>Changes</AppTable.Th>
                    <AppTable.Th>Devices</AppTable.Th>
                    <AppTable.Th>Created</AppTable.Th>
                    <AppTable.Th>Updated</AppTable.Th>
                    <AppTable.Th />
                  </AppTable.Tr>
                </AppTable.Thead>
                <AppTable.Tbody>
                  {pagedItems.map((item) => (
                    <AppTable.Tr key={item.id}>
                      <AppTable.Td>
                        <AppText className="fm-monospace" size="sm">
                          {item.id.slice(0, 8)}
                        </AppText>
                      </AppTable.Td>
                      <AppTable.Td>
                        <AppStatusBadge
                          value={deploymentHasFailure(item) ? 'FAILED' : item.state}
                          label={deploymentHasFailure(item) ? 'Failed' : undefined}
                        />
                      </AppTable.Td>
                      <AppTable.Td>{item.included_change_set_ids.length}</AppTable.Td>
                      <AppTable.Td>{formatDeploymentDevices(item)}</AppTable.Td>
                      <AppTable.Td>{formatDate(item.created_at)}</AppTable.Td>
                      <AppTable.Td>{formatDate(item.updated_at)}</AppTable.Td>
                      <AppTable.Td>
                        <AppGroup gap="xs" wrap="nowrap">
                          <AppActionButton intent="quiet" onClick={() => setDetailsId(item.id)}>
                            View details
                          </AppActionButton>
                          {deploymentHasFailure(item) && (
                            <AppActionButton
                              intent="secondary"
                              leftSection={<IconRefresh size={13} />}
                              loading={retryingId === item.id}
                              onClick={() => retry(item.id)}
                            >
                              Retry
                            </AppActionButton>
                          )}
                          {item.rollback_eligible && !item.rollback_state && (
                            <AppActionButton
                              intent="secondary"
                              loading={rollingBackId === item.id}
                              onClick={() => openRollbackDialog(item)}
                            >
                              Rollback
                            </AppActionButton>
                          )}
                        </AppGroup>
                      </AppTable.Td>
                    </AppTable.Tr>
                  ))}
                </AppTable.Tbody>
              </AppDataTable>
              <AdaptivePagination
                page={currentPage}
                pageSize={pageSize}
                total={visibleItems.length}
                onPageChange={setPage}
              />
            </>
          )}
        </AppCard>
      )}
      <AppDialog
        opened={Boolean(rollbackDialogId)}
        onClose={() => setRollbackDialogId(undefined)}
        title="Select Changesets to roll back"
        centered
      >
        <AppText size="sm" c="dimmed" mb="md">
          Each selected Changeset will get its own compensating Changeset and follow normal approval
          and deployment scheduling.
        </AppText>
        {rollbackDialogId &&
          items
            ?.find((item) => item.id === rollbackDialogId)
            ?.included_change_set_ids.map((changeSetId) => {
              const changeSet = rollbackChangeSets.find((item) => item.id === changeSetId);
              return (
                <AppGroup key={changeSetId} gap="sm" mb="sm">
                  <AppGroup gap="sm">
                    <AppCheckbox
                      aria-label={`Select Changeset ${changeSetId}`}
                      checked={selectedRollbackIds.includes(changeSetId)}
                      onChange={(event) => {
                        setSelectedRollbackIds((current) =>
                          event.currentTarget.checked
                            ? [...current, changeSetId]
                            : current.filter((id) => id !== changeSetId),
                        );
                      }}
                    />
                  </AppGroup>
                  {changeSet && (
                    <AppButton
                      size="compact-xs"
                      variant="subtle"
                      className="fm-monospace"
                      onClick={() => setRollbackDetails(changeSet)}
                    >
                      {changeSetId}
                    </AppButton>
                  )}
                </AppGroup>
              );
            })}
        <AppGroup justify="flex-end" mt="lg">
          <AppButton variant="subtle" onClick={() => setRollbackDialogId(undefined)}>
            Cancel
          </AppButton>
          <AppButton
            loading={rollingBackId === rollbackDialogId}
            disabled={selectedRollbackIds.length === 0}
            onClick={() => rollbackDialogId && rollback(rollbackDialogId)}
          >
            Create rollback Changesets
          </AppButton>
        </AppGroup>
      </AppDialog>
      <AppDialog
        opened={Boolean(rollbackDetails)}
        onClose={() => setRollbackDetails(undefined)}
        title="Changeset details"
        size="xl"
        centered
        closeButtonProps={{ 'aria-label': 'Close Changeset details' }}
        styles={{
          content: { maxHeight: 'calc(100dvh - 2rem)' },
          body: { overflowY: 'auto' },
        }}
      >
        {rollbackDetails && <ChangeSetDetails item={rollbackDetails} />}
      </AppDialog>
      <AppDialog
        opened={Boolean(selected)}
        onClose={() => setDetailsId(undefined)}
        title="Deployment details"
        size="xl"
        centered
        closeButtonProps={{ 'aria-label': 'Close deployment details' }}
        styles={{
          content: { maxHeight: 'calc(100dvh - 2rem)' },
          body: { overflowY: 'auto' },
        }}
      >
        {selected && <DeploymentDetails item={selected} />}
      </AppDialog>
    </AppPage>
  );
}

function formatRollbackError(reason: unknown): string {
  if (!(reason instanceof ApiError)) {
    return reason instanceof Error ? reason.message : 'Deployment rollback failed.';
  }
  const code = reason.details.code;
  if (code === 'ROLLBACK_SNAPSHOT_MISSING') {
    return 'This deployment predates rollback snapshots, so the application cannot safely reconstruct its previous configuration. Deployments created after rollback support was enabled can be rolled back with a compensating Changeset.';
  }
  if (code === 'ROLLBACK_CONFLICT') {
    return 'Rollback stopped because the affected resource changed after this deployment. Review the current rule/object before creating a manual compensating Changeset.';
  }
  return reason.message;
}

function deploymentStatusKey(item: Deployment): string {
  return deploymentHasFailure(item) ? 'FAILED' : item.state;
}

function deploymentStatusLabel(value: string): string {
  return value
    .toLowerCase()
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function deploymentHasFailure(item: Deployment): boolean {
  return (
    typeof item.failure_info.code === 'string' ||
    ['FAILED', 'UNKNOWN', 'RECONCILIATION_REQUIRED'].includes(item.state)
  );
}

function formatDeploymentDevices(item: Deployment): string {
  const reported = item.device_results
    .map((result) => {
      const name = result.name;
      const uid = result.uid ?? result.device_id;
      return typeof name === 'string' ? name : typeof uid === 'string' ? uid : null;
    })
    .filter((value): value is string => Boolean(value));
  if (reported.length > 0) {
    return reported.length <= 2
      ? reported.join(', ')
      : `${reported.slice(0, 2).join(', ')} +${reported.length - 2} more`;
  }
  if (item.target_device_ids.length > 0) {
    return item.target_device_ids.length <= 2
      ? item.target_device_ids.map((id) => item.device_names[id] ?? id).join(', ')
      : `${item.target_device_ids
          .slice(0, 2)
          .map((id) => item.device_names[id] ?? id)
          .join(', ')} +${item.target_device_ids.length - 2} more`;
  }
  const planned = item.plan_snapshot.provider_jobs;
  if (Array.isArray(planned)) {
    const ids = planned.flatMap((job) => {
      if (typeof job !== 'object' || job === null) return [];
      const provider = (job as Record<string, unknown>).provider;
      if (typeof provider !== 'object' || provider === null) return [];
      const deviceList = (provider as Record<string, unknown>).deviceList;
      return Array.isArray(deviceList)
        ? deviceList.filter((id): id is string => typeof id === 'string')
        : [];
    });
    if (ids.length > 0) {
      const names = ids.map((id) => item.device_names[id] ?? id);
      return names.length <= 2
        ? names.join(', ')
        : `${names.slice(0, 2).join(', ')} +${names.length - 2} more`;
    }
  }
  return '—';
}

function DeploymentDetails({ item }: { item: Deployment }) {
  const [changeSets, setChangeSets] = useState<ChangeSet[]>([]);
  const [changeSetDetails, setChangeSetDetails] = useState<ChangeSet>();
  const providerMessages = Array.isArray(item.failure_info.provider_messages)
    ? item.failure_info.provider_messages
    : [];
  return (
    <div>
      <AppGroup justify="space-between" align="start" mb="md">
        <div>
          <AppText fw={650}>Batch {item.id}</AppText>
          <AppText size="sm" c="dimmed">
            Provider deployment operation
          </AppText>
        </div>
        <AppStatusBadge value={item.state} />
        {item.rollback_state && <AppStatusBadge value={item.rollback_state} />}
      </AppGroup>
      <AppPaper withBorder p="md" mb="md">
        <AppGroup gap="xl" align="start" wrap="wrap">
          <DeploymentDetail label="Created" value={formatDate(item.created_at)} />
          <DeploymentDetail label="Last updated" value={formatDate(item.updated_at)} />
          <DeploymentDetail
            label="Provider task"
            value={item.external_operation_id ?? 'Not assigned'}
            code
          />
          <DeploymentDetail
            label="Scheduled"
            value={formatDate(
              typeof item.plan_snapshot.scheduled_for === 'string'
                ? item.plan_snapshot.scheduled_for
                : null,
            )}
          />
          <DeploymentDetail label="Changes" value={String(item.included_change_set_ids.length)} />
          <DeploymentDetail label="Devices" value={formatDeploymentDevices(item)} />
        </AppGroup>
      </AppPaper>
      {typeof item.failure_info.code === 'string' && (
        <AppPaper withBorder p="md" mb="md">
          <AppText fw={650} c="red">
            Failure
          </AppText>
          <AppText size="sm" c="red">
            {item.failure_info.code}
          </AppText>
          {Array.isArray(item.failure_info.provider_statuses) && (
            <AppText size="sm" mt={4}>
              Provider status: {item.failure_info.provider_statuses.join(', ')}
            </AppText>
          )}
          {providerMessages.map((message, index) => (
            <AppText key={`deployment-provider-${index}`} size="sm" mt={4}>
              {formatProviderMessage(message)}
            </AppText>
          ))}
        </AppPaper>
      )}
      {typeof item.rollback_failure_info.code === 'string' && (
        <AppPaper withBorder p="md" mb="md">
          <AppText fw={650} c="red">
            Rollback failure
          </AppText>
          <AppText size="sm" c="red">
            {String(item.rollback_failure_info.code)}
          </AppText>
        </AppPaper>
      )}
      {item.state === 'DEPLOYED' && !item.rollback_eligible && item.rollback_unavailable_reason && (
        <AppPaper withBorder p="md" mb="md">
          <AppText fw={650}>Rollback unavailable</AppText>
          <AppText size="sm" c="dimmed">
            {item.rollback_unavailable_reason}
          </AppText>
        </AppPaper>
      )}
      <AppText fw={650} mb="xs">
        Included Changesets
      </AppText>
      {item.included_change_set_ids.map((changeSetId) => (
        <AppButton
          key={changeSetId}
          size="xs"
          variant="subtle"
          className="fm-monospace"
          onClick={() => {
            const existing = changeSets.find((changeSet) => changeSet.id === changeSetId);
            if (existing) {
              setChangeSetDetails(existing);
              return;
            }
            void loadDeploymentChangeSets(item.id).then((loaded) => {
              setChangeSets(loaded);
              const selected = loaded.find((changeSet) => changeSet.id === changeSetId);
              if (selected) setChangeSetDetails(selected);
            });
          }}
        >
          {changeSetId}
        </AppButton>
      ))}
      <AppDialog
        opened={Boolean(changeSetDetails)}
        onClose={() => setChangeSetDetails(undefined)}
        title="Changeset details"
        size="xl"
        centered
        closeButtonProps={{ 'aria-label': 'Close Changeset details' }}
        styles={{
          content: { maxHeight: 'calc(100dvh - 2rem)' },
          body: { overflowY: 'auto' },
        }}
      >
        {changeSetDetails && <ChangeSetDetails item={changeSetDetails} />}
      </AppDialog>
    </div>
  );
}

function DeploymentDetail({
  label,
  value,
  code = false,
}: {
  label: string;
  value: string;
  code?: boolean;
}) {
  return (
    <div>
      <AppText size="xs" c="dimmed">
        {label}
      </AppText>
      <AppText size="sm" className={code ? 'fm-monospace' : undefined}>
        {value}
      </AppText>
    </div>
  );
}

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Not scheduled';
}

function formatProviderMessage(value: unknown): string {
  const message =
    typeof value === 'object' && value !== null && 'message' in value
      ? String(value.message)
      : String(value);
  // Provider identifiers are already shown in the structured device/task fields. Keep the
  // primary failure copy readable instead of exposing an opaque UUID inline.
  return message
    .replace(/\s*\(([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\)/gi, '')
    .replace(
      /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
      'provider device',
    );
}
