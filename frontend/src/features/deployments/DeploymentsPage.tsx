import { useEffect, useState } from 'react';
import { IconRocket, IconRefresh } from '@tabler/icons-react';
import {
  ApiError,
  loadDeploymentChangeSets,
  loadDeployments,
  retryDeployment,
  rollbackDeployment,
  type ChangeSet,
  type Deployment,
} from '../../api/client';
import {
  AppButton,
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
  AppStatusBadge,
  AppTable,
  AppText,
  MetricCard,
} from '../../ui';
import { ChangeSetDetails } from '../changesets/ChangeSetPanel';


export function DeploymentsPage({
  onViewChangeSet,
}: {
  onViewChangeSet?: (changeSetId: string) => void;
} = {}) {
  const [items, setItems] = useState<Deployment[] | null>(null);
  const [error, setError] = useState<string>();
  const [refreshing, setRefreshing] = useState(false);
  const [retryingId, setRetryingId] = useState<string>();
  const [rollingBackId, setRollingBackId] = useState<string>();
  const [rollbackDialogId, setRollbackDialogId] = useState<string>();
  const [selectedRollbackIds, setSelectedRollbackIds] = useState<string[]>([]);
  const [rollbackChangeSets, setRollbackChangeSets] = useState<ChangeSet[]>([]);
  const [rollbackDetails, setRollbackDetails] = useState<ChangeSet>();
  const [detailsId, setDetailsId] = useState<string>();
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
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : 'ChangeSets could not be loaded.'));
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
      .catch((reason: unknown) =>
        setError(formatRollbackError(reason)),
      )
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
  const counts = {
    active: items?.filter((item) => ['SCHEDULED', 'READY', 'DEPLOYING'].includes(item.state) || item.rollback_state === 'ROLLING_BACK').length ?? 0,
    completed: items?.filter((item) => item.state === 'DEPLOYED' && item.rollback_state !== 'ROLLED_BACK').length ?? 0,
    failed: items?.filter((item) => ['FAILED', 'UNKNOWN', 'RECONCILIATION_REQUIRED'].includes(item.state)).length ?? 0,
  };
  return (
    <AppPage
      eyebrow="Operations"
      title="Deployments"
      description="Connector-level deployment batches for staged provider changes. Status refreshes automatically."
    >
      <AppGroup justify="space-between" mb="lg">
        <AppGroup gap="xs">
          <IconRocket size={18} />
          <AppText size="sm" c="dimmed">Automatic deployment runs every 15 minutes when enabled.</AppText>
        </AppGroup>
        <AppButton variant="light" leftSection={<IconRefresh size={15} />} loading={refreshing} onClick={refresh}>
          Refresh
        </AppButton>
      </AppGroup>
      {error && <AppErrorState message={error} />}
      {!error && !items && <AppLoadingState label="Loading deployments" />}
      {items && (
        <AppSimpleGrid cols={{ base: 1, sm: 3 }} mb="lg">
          <MetricCard label="In progress" value={counts.active} detail="Scheduled, queued, or deploying" icon={<IconRocket size={18} />} />
          <MetricCard label="Completed" value={counts.completed} detail="Provider confirmed" icon={<IconRocket size={18} />} />
          <MetricCard label="Needs attention" value={counts.failed} detail="Failed or uncertain" icon={<IconRocket size={18} />} />
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
          <AppDataTable label="Deployments">
            <AppTable striped highlightOnHover>
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
              {items.map((item) => (
                <AppTable.Tr key={item.id}>
                  <AppTable.Td><AppText className="fm-monospace" size="sm">{item.id.slice(0, 8)}</AppText></AppTable.Td>
                  <AppTable.Td>
                    <AppStatusBadge value={item.state} />
                    {typeof item.failure_info.code === 'string' && <AppText size="xs" c="red">{item.failure_info.code}</AppText>}
                    {Array.isArray(item.failure_info.provider_messages) && item.failure_info.provider_messages.map((message, index) => (
                      <AppText key={`${item.id}-provider-${index}`} size="xs" c="dimmed">
                        {formatProviderMessage(message)}
                      </AppText>
                    ))}
                    {['FAILED', 'UNKNOWN', 'RECONCILIATION_REQUIRED'].includes(item.state) && (
                      <AppButton
                        size="compact-xs"
                        variant="light"
                        leftSection={<IconRefresh size={13} />}
                        loading={retryingId === item.id}
                        onClick={() => retry(item.id)}
                      >
                        Retry
                      </AppButton>
                    )}
                    {item.rollback_eligible && !item.rollback_state && (
                      <AppButton
                        size="compact-xs"
                        variant="light"
                        color="orange"
                        loading={rollingBackId === item.id}
                        onClick={() => openRollbackDialog(item)}
                      >
                        Create rollback ChangeSet
                      </AppButton>
                    )}
                  </AppTable.Td>
                  <AppTable.Td>{item.included_change_set_ids.length}</AppTable.Td>
                  <AppTable.Td>{formatDeploymentDevices(item)}</AppTable.Td>
                  <AppTable.Td>{formatDate(item.created_at)}</AppTable.Td>
                  <AppTable.Td>{formatDate(item.updated_at)}</AppTable.Td>
                  <AppTable.Td>
                    <AppButton size="xs" variant="subtle" onClick={() => setDetailsId(item.id)}>
                      View details
                    </AppButton>
                  </AppTable.Td>
                </AppTable.Tr>
              ))}
            </AppTable.Tbody>
            </AppTable>
          </AppDataTable>
        </AppCard>
      )}
      <AppDialog
        opened={Boolean(rollbackDialogId)}
        onClose={() => setRollbackDialogId(undefined)}
        title="Select ChangeSets to roll back"
        centered
      >
        <AppText size="sm" c="dimmed" mb="md">
          Each selected ChangeSet will get its own compensating ChangeSet and follow normal approval and deployment scheduling.
        </AppText>
        {rollbackDialogId && items?.find((item) => item.id === rollbackDialogId)?.included_change_set_ids.map((changeSetId) => {
          const changeSet = rollbackChangeSets.find((item) => item.id === changeSetId);
          return (
            <AppGroup key={changeSetId} gap="sm" mb="sm">
              <AppGroup gap="sm">
                <AppCheckbox
                  aria-label={`Select ChangeSet ${changeSetId}`}
                  checked={selectedRollbackIds.includes(changeSetId)}
                  onChange={(event) => {
                    setSelectedRollbackIds((current) => event.currentTarget.checked
                      ? [...current, changeSetId]
                    : current.filter((id) => id !== changeSetId));
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
          <AppButton variant="subtle" onClick={() => setRollbackDialogId(undefined)}>Cancel</AppButton>
          <AppButton
            loading={rollingBackId === rollbackDialogId}
            disabled={selectedRollbackIds.length === 0}
            onClick={() => rollbackDialogId && rollback(rollbackDialogId)}
          >
            Create rollback ChangeSets
          </AppButton>
        </AppGroup>
      </AppDialog>
      <AppDialog
        opened={Boolean(rollbackDetails)}
        onClose={() => setRollbackDetails(undefined)}
        title="ChangeSet details"
        size="xl"
        centered
        closeButtonProps={{ 'aria-label': 'Close ChangeSet details' }}
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
        {selected && (
          <DeploymentDetails item={selected} />
        )}
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
    return 'This deployment predates rollback snapshots, so the application cannot safely reconstruct its previous configuration. Deployments created after rollback support was enabled can be rolled back with a compensating ChangeSet.';
  }
  if (code === 'ROLLBACK_CONFLICT') {
    return 'Rollback stopped because the affected resource changed after this deployment. Review the current rule/object before creating a manual compensating ChangeSet.';
  }
  return reason.message;
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
      : `${item.target_device_ids.slice(0, 2).map((id) => item.device_names[id] ?? id).join(', ')} +${item.target_device_ids.length - 2} more`;
  }
  const planned = item.plan_snapshot.provider_jobs;
  if (Array.isArray(planned)) {
    const ids = planned.flatMap((job) => {
      if (typeof job !== 'object' || job === null) return [];
      const provider = (job as Record<string, unknown>).provider;
      if (typeof provider !== 'object' || provider === null) return [];
      const deviceList = (provider as Record<string, unknown>).deviceList;
      return Array.isArray(deviceList) ? deviceList.filter((id): id is string => typeof id === 'string') : [];
    });
    if (ids.length > 0) {
      const names = ids.map((id) => item.device_names[id] ?? id);
      return names.length <= 2 ? names.join(', ') : `${names.slice(0, 2).join(', ')} +${names.length - 2} more`;
    }
  }
  return '—';
}

function DeploymentDetails({
  item,
}: {
  item: Deployment;
}) {
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
          <AppText size="sm" c="dimmed">Provider deployment operation</AppText>
        </div>
        <AppStatusBadge value={item.state} />
        {item.rollback_state && <AppStatusBadge value={item.rollback_state} />}
      </AppGroup>
      <AppPaper withBorder p="md" mb="md">
        <AppGroup gap="xl" align="start" wrap="wrap">
          <DeploymentDetail label="Created" value={formatDate(item.created_at)} />
          <DeploymentDetail label="Last updated" value={formatDate(item.updated_at)} />
          <DeploymentDetail label="Provider task" value={item.external_operation_id ?? 'Not assigned'} code />
          <DeploymentDetail
            label="Scheduled"
            value={formatDate(typeof item.plan_snapshot.scheduled_for === 'string' ? item.plan_snapshot.scheduled_for : null)}
          />
          <DeploymentDetail label="Changes" value={String(item.included_change_set_ids.length)} />
          <DeploymentDetail
            label="Devices"
            value={formatDeploymentDevices(item)}
          />
        </AppGroup>
      </AppPaper>
      {typeof item.failure_info.code === 'string' && (
        <AppPaper withBorder p="md" mb="md">
          <AppText fw={650} c="red">Failure</AppText>
          <AppText size="sm" c="red">{item.failure_info.code}</AppText>
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
          <AppText fw={650} c="red">Rollback failure</AppText>
          <AppText size="sm" c="red">{String(item.rollback_failure_info.code)}</AppText>
        </AppPaper>
      )}
      {item.state === 'DEPLOYED' && !item.rollback_eligible && item.rollback_unavailable_reason && (
        <AppPaper withBorder p="md" mb="md">
          <AppText fw={650}>Rollback unavailable</AppText>
          <AppText size="sm" c="dimmed">{item.rollback_unavailable_reason}</AppText>
        </AppPaper>
      )}
      <AppText fw={650} mb="xs">Included ChangeSets</AppText>
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
        title="ChangeSet details"
        size="xl"
        centered
        closeButtonProps={{ 'aria-label': 'Close ChangeSet details' }}
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

function DeploymentDetail({ label, value, code = false }: { label: string; value: string; code?: boolean }) {
  return (
    <div>
      <AppText size="xs" c="dimmed">{label}</AppText>
      <AppText size="sm" className={code ? 'fm-monospace' : undefined}>{value}</AppText>
    </div>
  );
}

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Not scheduled';
}

function formatProviderMessage(value: unknown): string {
  if (typeof value === 'object' && value !== null && 'message' in value) {
    return String(value.message);
  }
  return String(value);
}
