import { useEffect, useState } from 'react';
import { IconAlertTriangle, IconCircleCheck, IconFileDiff, IconLoader2 } from '@tabler/icons-react';

import {
  ApiError,
  changeSetAction,
  deleteChangeSet,
  loadChangeSets,
  type ChangeSet,
  type DelegatedContext,
} from '../../api/client';
import {
  AppAlert as Alert,
  AppActionButton,
  AppCard as Card,
  AppDataTable,
  AppDialog as Dialog,
  AppDivider as Divider,
  AppEmptyState,
  AppGroup as Group,
  AppLoadingState,
  AppPaper as Paper,
  AppSimpleGrid as SimpleGrid,
  AppStack as Stack,
  AppStatusBadge,
  AppTable as Table,
  AppText as Text,
  AppTitle as Title,
  MetricCard,
} from '../../ui';
import { retryableChangeSet } from './changeSetRetry';
import { AdaptivePagination, useAdaptivePageSize } from '../shared/AdaptivePagination';

const SUBMITTED_STATES = new Set([
  'DRAFT',
  'VALIDATION_FAILED',
  'READY',
  'APPROVED',
  'QUEUED',
  'EXECUTING',
  'SUCCEEDED',
  'FAILED',
  'PARTIALLY_SUCCEEDED',
  'CONFLICT',
  'RECONCILIATION_REQUIRED',
  'REJECTED',
]);
const FAILURE_STATES = new Set([
  'VALIDATION_FAILED',
  'FAILED',
  'PARTIALLY_SUCCEEDED',
  'CONFLICT',
  'RECONCILIATION_REQUIRED',
]);
const FAILURE_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

export function changeSetStatusLabel(item: Pick<ChangeSet, 'state' | 'approval_required'>) {
  if (item.state === 'READY' && item.approval_required) return 'Awaiting approval';
  const labels: Record<string, string> = {
    FAILED: 'Failed',
    SUCCEEDED: 'Succeeded',
    VALIDATION_FAILED: 'Validation failed',
    PARTIALLY_SUCCEEDED: 'Partially succeeded',
    CONFLICT: 'Conflict',
    RECONCILIATION_REQUIRED: 'Reconciliation required',
    REJECTED: 'Rejected',
  };
  return labels[item.state] ?? item.state.charAt(0) + item.state.slice(1).toLowerCase();
}

export function ChangeSetPanel({
  activeGroupId,
  context,
}: {
  activeGroupId: string;
  context: DelegatedContext;
}) {
  const [items, setItems] = useState<ChangeSet[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [retryingId, setRetryingId] = useState('');
  const [executingId, setExecutingId] = useState('');
  const [deletingId, setDeletingId] = useState('');
  const [detailsId, setDetailsId] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = useAdaptivePageSize();
  const selected = items.find((item) => item.id === detailsId);

  useEffect(() => {
    let active = true;
    const load = () =>
      loadChangeSets(activeGroupId)
        .then((rows) => {
          if (!active) return;
          setItems(
            rows.filter(
              (item) =>
                item.access_policy_id === context.policy.id && SUBMITTED_STATES.has(item.state),
            ),
          );
        })
        .catch((reason: unknown) => {
          if (active) setError(message(reason));
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    void load();
    const refresh = window.setInterval(() => void load(), 3_000);
    return () => {
      active = false;
      window.clearInterval(refresh);
    };
  }, [activeGroupId, context.policy.id]);

  useEffect(() => {
    const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
    setPage((current) => Math.min(current, pageCount));
  }, [items.length, pageSize]);

  const retry = async (item: ChangeSet) => {
    if (
      !window.confirm(
        `Retry ${item.title}?\n\nCurrent authorization, provider capabilities, and revisions will be checked again before it is queued.`,
      )
    )
      return;
    setRetryingId(item.id);
    setError('');
    try {
      const updated = await changeSetAction(item.id, activeGroupId, 'retry');
      setItems((current) => current.map((row) => (row.id === updated.id ? updated : row)));
    } catch (reason) {
      setError(message(reason));
    } finally {
      setRetryingId('');
    }
  };

  const execute = async (item: ChangeSet) => {
    if (
      !window.confirm(
        `Execute ${item.title}?\n\nThe validated operations will be queued for provider execution.`,
      )
    )
      return;
    setExecutingId(item.id);
    setError('');
    try {
      const updated = await changeSetAction(item.id, activeGroupId, 'execute');
      setItems((current) => current.map((row) => (row.id === updated.id ? updated : row)));
    } catch (reason) {
      setError(message(reason));
    } finally {
      setExecutingId('');
    }
  };

  const remove = async (item: ChangeSet) => {
    if (!window.confirm(`Delete the ${item.state.toLowerCase()} Changeset “${item.title}”?`))
      return;
    setDeletingId(item.id);
    setError('');
    try {
      await deleteChangeSet(activeGroupId, item.id);
      setItems((current) => current.filter((row) => row.id !== item.id));
      setDetailsId((current) => (current === item.id ? '' : current));
    } catch (reason) {
      setError(message(reason));
    } finally {
      setDeletingId('');
    }
  };

  const inProgress = items.filter((item) => ['QUEUED', 'EXECUTING'].includes(item.state)).length;
  const failureWindowStart = Date.now() - FAILURE_WINDOW_MS;
  const recentSuccessful = items.filter(
    (item) => item.state === 'SUCCEEDED' && Date.parse(item.updated_at) >= failureWindowStart,
  ).length;
  const recentFailures = items.filter(
    (item) => FAILURE_STATES.has(item.state) && Date.parse(item.updated_at) >= failureWindowStart,
  ).length;
  const pagedItems = items.slice((page - 1) * pageSize, page * pageSize);

  if (loading) return <AppLoadingState label="Loading Changesets" />;

  return (
    <Stack gap="lg">
      <SimpleGrid cols={{ base: 1, xs: 2, lg: 4 }}>
        <MetricCard
          label="Tracked"
          value={items.length}
          detail="Validated and submitted Changesets"
          icon={<IconFileDiff size={19} />}
        />
        <MetricCard
          label="In progress"
          value={inProgress}
          detail="Queued or executing"
          icon={<IconLoader2 size={19} />}
        />
        <MetricCard
          label="Succeeded (30 days)"
          value={recentSuccessful}
          detail="Provider writes completed"
          icon={<IconCircleCheck size={19} />}
        />
        <MetricCard
          label="Failures (30 days)"
          value={recentFailures}
          detail="Validation, execution, or conflict failures"
          icon={<IconAlertTriangle size={19} />}
        />
      </SimpleGrid>
      <Card component="section" aria-labelledby="changeset-heading" id="changes-workflow">
        <Group justify="space-between" align="start" mb="md">
          <div>
            <Title id="changeset-heading" order={2} size="h4">
              Submitted Changesets
            </Title>
            <Text size="sm" c="dimmed">
              Provider configuration submissions and their current execution status.
            </Text>
          </div>
        </Group>

        {error && (
          <Alert color="red" title="Changeset action could not be completed" mb="md" role="alert">
            {error}
          </Alert>
        )}

        {!error && items.length === 0 ? (
          <AppEmptyState
            title="No Changesets for this policy"
            description="Draft, validated, and submitted Changesets appear here."
          />
        ) : (
          items.length > 0 && (
            <div className="fm-changeset-table">
              <AppDataTable label="Submitted Changesets">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Changeset</Table.Th>
                    <Table.Th>Operations</Table.Th>
                    <Table.Th>Provider</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>Updated</Table.Th>
                    <Table.Th>Actions</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {pagedItems.map((item) => (
                    <Table.Tr key={item.id}>
                      <Table.Td>
                        <Text fw={650}>{item.title}</Text>
                        {item.description && (
                          <Text size="xs" c="dimmed" lineClamp={1}>
                            {item.description}
                          </Text>
                        )}
                      </Table.Td>
                      <Table.Td>{item.operations.length}</Table.Td>
                      <Table.Td>
                        {context.provider_name} ({context.provider_type.toUpperCase()})
                      </Table.Td>
                      <Table.Td>
                        <AppStatusBadge value={item.state} label={changeSetStatusLabel(item)} />
                      </Table.Td>
                      <Table.Td>{new Date(item.updated_at).toLocaleString()}</Table.Td>
                      <Table.Td>
                        <Group gap="xs" wrap="nowrap">
                          <AppActionButton intent="quiet" onClick={() => setDetailsId(item.id)}>
                            View details
                          </AppActionButton>
                          {['READY', 'APPROVED'].includes(item.state) &&
                            !(item.state === 'READY' && item.approval_required) && (
                              <AppActionButton
                                intent="secondary"
                                loading={executingId === item.id}
                                disabled={Boolean(retryingId) || Boolean(executingId)}
                                onClick={() => void execute(item)}
                              >
                                Execute
                              </AppActionButton>
                            )}
                          {['DRAFT', 'VALIDATION_FAILED', 'READY'].includes(item.state) && (
                            <AppActionButton
                              intent="quiet-danger"
                              loading={deletingId === item.id}
                              disabled={
                                Boolean(retryingId) || Boolean(executingId) || Boolean(deletingId)
                              }
                              onClick={() => void remove(item)}
                            >
                              Delete
                            </AppActionButton>
                          )}
                          {retryableChangeSet(item) && (
                            <AppActionButton
                              intent="secondary"
                              loading={retryingId === item.id}
                              disabled={Boolean(retryingId) || Boolean(executingId)}
                              onClick={() => void retry(item)}
                            >
                              Retry
                            </AppActionButton>
                          )}
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </AppDataTable>
              <AdaptivePagination
                page={page}
                pageSize={pageSize}
                total={items.length}
                onPageChange={setPage}
              />
            </div>
          )
        )}

        <Dialog
          opened={Boolean(selected)}
          onClose={() => setDetailsId('')}
          title="Changeset details"
          size="xl"
          centered
          closeButtonProps={{ 'aria-label': 'Close Changeset details' }}
          styles={{
            content: { maxHeight: 'calc(100dvh - 2rem)' },
            body: { overflowY: 'auto' },
          }}
        >
          {selected && <ChangeSetDetails item={selected} context={context} />}
        </Dialog>
      </Card>
    </Stack>
  );
}

export function ChangeSetDetails({
  item,
  context,
}: {
  item: ChangeSet;
  context?: DelegatedContext;
}) {
  const failures = failureCodes(item);
  const providerDetails = providerFailureDetails(item);
  const pendingWarnings = pendingChangeWarnings(item);
  return (
    <Stack gap="md">
      <Group justify="space-between" align="start">
        <div>
          <Title order={3} size="h4">
            {item.title}
          </Title>
          {item.description && (
            <Text size="sm" c="dimmed" mt={4}>
              {item.description}
            </Text>
          )}
        </div>
        <AppStatusBadge value={item.state} label={changeSetStatusLabel(item)} />
      </Group>

      <Paper withBorder p="md">
        <Group gap="xl" align="start">
          <Detail
            label="Provider"
            value={
              context
                ? `${context.provider_name} (${context.provider_type.toUpperCase()})`
                : (item.operations[0]?.manager_id ?? 'Provider manager not specified')
            }
          />
          <Detail label="Requested by" value={requestingUser(item)} />
          <Detail label="Created" value={new Date(item.created_at).toLocaleString()} />
          <Detail label="Last updated" value={new Date(item.updated_at).toLocaleString()} />
          <Detail label="Changeset ID" value={item.id} code />
        </Group>
      </Paper>

      {failures.length > 0 && (
        <Alert color="red" title="Failure details">
          {failures.map(humanize).join(' · ')}
          {providerDetails.length > 0 && (
            <Stack gap={2} mt="xs">
              {providerDetails.map((detail, index) => (
                <Text key={`${detail}-${index}`} size="sm">
                  {detail}
                </Text>
              ))}
            </Stack>
          )}
        </Alert>
      )}

      {pendingWarnings.length > 0 && (
        <Alert color="yellow" title="Other provider changes are pending">
          This Changeset was applied independently after re-reading its affected resources. Provider
          deployment remains separate and may also deploy changes outside this Changeset.
          {pendingWarnings.some((warning) => warning.actors.length > 0) && (
            <Text size="xs" mt={5}>
              Reported provider actors:{' '}
              {[...new Set(pendingWarnings.flatMap((warning) => warning.actors))].join(', ')}
            </Text>
          )}
        </Alert>
      )}

      {item.state === 'REJECTED' && (
        <Alert color="red" title="Rejected by an approver">
          Rejected by {item.rejected_by_display_name ?? item.rejected_by_email ?? 'an approver'}:{' '}
          {item.rejection_reason ?? 'No rejection reason was provided.'}
        </Alert>
      )}

      <div>
        <Text fw={650} mb="xs">
          Operations ({item.operations.length})
        </Text>
        <AppDataTable label={`Operations in ${item.title}`}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>#</Table.Th>
              <Table.Th>Operation</Table.Th>
              <Table.Th>Object</Table.Th>
              <Table.Th>Value</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Result</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {[...item.operations]
              .sort((left, right) => left.sequence - right.sequence)
              .map((operation) => {
                const result = providerResult(item, operation.id);
                return (
                  <Table.Tr key={operation.id}>
                    <Table.Td>{operation.sequence}</Table.Td>
                    <Table.Td>{humanize(operation.kind)}</Table.Td>
                    <Table.Td>
                      <Text size="sm" fw={600}>
                        {operationName(operation.payload)}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {humanize(stringValue(operation.payload.object_type) || 'resource')}
                      </Text>
                    </Table.Td>
                    <Table.Td>{operationValue(operation.payload, operation.resolution)}</Table.Td>
                    <Table.Td>
                      <AppStatusBadge value={stringValue(result.status) || operation.status} />
                    </Table.Td>
                    <Table.Td>
                      <OperationResult result={result} fallback={operation.failure_info} />
                    </Table.Td>
                  </Table.Tr>
                );
              })}
          </Table.Tbody>
        </AppDataTable>
      </div>

      {item.transactions.length > 0 && (
        <>
          <Divider />
          <div>
            <Text fw={650} mb="xs">
              Provider attempts ({item.transactions.length})
            </Text>
            <AppDataTable label={`Provider attempts for ${item.title}`}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Updated</Table.Th>
                  <Table.Th>Provider operation</Table.Th>
                  <Table.Th>Reconciliation</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {item.transactions.map((transaction) => (
                  <Table.Tr key={transaction.id}>
                    <Table.Td>
                      <AppStatusBadge value={transaction.state} />
                    </Table.Td>
                    <Table.Td>{new Date(transaction.updated_at).toLocaleString()}</Table.Td>
                    <Table.Td>
                      <Text size="xs" className="fm-code">
                        {transaction.external_operation_id ?? 'Not assigned'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {transaction.reconciliation_required ? 'Required' : 'Not required'}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </AppDataTable>
          </div>
        </>
      )}
    </Stack>
  );
}

function Detail({ label, value, code = false }: { label: string; value: string; code?: boolean }) {
  return (
    <div>
      <Text size="xs" c="dimmed">
        {label}
      </Text>
      <Text size="sm" fw={600} className={code ? 'fm-code' : undefined}>
        {value}
      </Text>
    </div>
  );
}

function OperationResult({
  result,
  fallback,
}: {
  result: Record<string, unknown>;
  fallback: Record<string, unknown>;
}) {
  const failure = record(result.failure);
  const code = stringValue(failure.code) || stringValue(fallback.code);
  const providerMessages = Array.isArray(failure.provider_messages)
    ? failure.provider_messages
        .map((item) => {
          const message = record(item);
          return (
            stringValue(message.description) ||
            stringValue(message.details) ||
            stringValue(message.errorCode) ||
            stringValue(message.code)
          );
        })
        .filter(Boolean)
    : [];
  if (code)
    return (
      <Stack gap={2}>
        <Text size="sm" c="red">
          {humanize(code)}
        </Text>
        {providerMessages.map((message, index) => (
          <Text key={`${message}-${index}`} size="xs" c="red">
            {message}
          </Text>
        ))}
      </Stack>
    );
  const warned = Array.isArray(result.warnings) && result.warnings.length > 0;
  if (result.mutated === true)
    return (
      <Stack gap={2}>
        <Text size="sm">Provider updated</Text>
        {warned && (
          <Text size="xs" c="yellow">
            Other pending changes exist
          </Text>
        )}
      </Stack>
    );
  if (result.mutated === false)
    return (
      <Stack gap={2}>
        <Text size="sm" c="dimmed">
          No provider change
        </Text>
        {warned && (
          <Text size="xs" c="yellow">
            Other pending changes exist
          </Text>
        )}
      </Stack>
    );
  return (
    <Text size="sm" c="dimmed">
      No result reported
    </Text>
  );
}

function providerResult(item: ChangeSet, operationId: string) {
  for (const transaction of item.transactions) {
    const match = transaction.operation_results.find(
      (result) => stringValue(result.operation_id) === operationId,
    );
    if (match) return match;
  }
  return {};
}

function operationName(payload: Record<string, unknown>) {
  return (
    stringValue(payload.name) ||
    stringValue(payload.provider_name) ||
    stringValue(payload.expected_provider_name) ||
    'Unnamed resource'
  );
}

function requestingUser(item: ChangeSet) {
  const name = item.creator_display_name?.trim();
  const email = item.creator_email?.trim();
  if (name && email) return `${name} (${email})`;
  return name || email || item.creator_id;
}

function operationValue(payload: Record<string, unknown>, resolution: Record<string, unknown>) {
  return (
    stringValue(resolution.normalized_value) ||
    stringValue(payload.normalized_value) ||
    stringValue(payload.value) ||
    '—'
  );
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringValue(value: unknown) {
  return typeof value === 'string' ? value : '';
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
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .replace(/\bIp\b/g, 'IP');
}

function failureCodes(item: ChangeSet) {
  const codes = new Set<string>();
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (typeof value !== 'object' || value === null) return;
    Object.entries(value).forEach(([key, nested]) => {
      if (['code', 'error_code', 'reason'].includes(key) && typeof nested === 'string') {
        codes.add(nested);
      } else {
        visit(nested);
      }
    });
  };
  visit(item.failure_info);
  item.operations.forEach((operation) => visit(operation.failure_info));
  item.transactions.forEach((transaction) => visit(transaction.failure_info));
  return [...codes];
}

function providerFailureDetails(item: ChangeSet) {
  const details: string[] = [];
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (typeof value !== 'object' || value === null) return;
    const recordValue = value as Record<string, unknown>;
    if (
      typeof recordValue.provider_status === 'number' ||
      typeof recordValue.provider_status === 'string'
    ) {
      details.push(`Provider returned HTTP ${String(recordValue.provider_status)}`);
    }
    if (Array.isArray(recordValue.provider_messages)) {
      recordValue.provider_messages.forEach((message) => {
        const entry = record(message);
        const text =
          stringValue(entry.description) ||
          stringValue(entry.details) ||
          stringValue(entry.message) ||
          stringValue(entry.error) ||
          stringValue(entry.reason) ||
          stringValue(entry.messages);
        if (text) details.push(text);
      });
    }
    Object.values(recordValue).forEach(visit);
  };
  item.transactions.forEach((transaction) => visit(transaction.failure_info));
  item.operations.forEach((operation) => visit(operation.failure_info));
  return [...new Set(details)].slice(0, 5);
}

function pendingChangeWarnings(item: ChangeSet) {
  const warnings: Array<{ actors: string[] }> = [];
  item.transactions.forEach((transaction) => {
    transaction.operation_results.forEach((result) => {
      if (!Array.isArray(result.warnings)) return;
      result.warnings.forEach((value) => {
        const warning = record(value);
        if (stringValue(warning.code) !== 'OTHER_PENDING_CHANGES_PRESENT') return;
        warnings.push({
          actors: Array.isArray(warning.actors)
            ? warning.actors.filter((actor): actor is string => typeof actor === 'string')
            : [],
        });
      });
    });
  });
  return warnings;
}

function message(error: unknown) {
  if (!(error instanceof ApiError)) return 'The request failed.';
  const requiredState = error.details.required_state;
  const approvalRequired =
    error.code === 'INVALID_CHANGE_SET_STATE' &&
    Array.isArray(requiredState) &&
    requiredState.includes('APPROVED');
  if (approvalRequired) {
    return `This Changeset requires approval before it can be executed. An authorized approver must approve it first. Reference: ${error.correlationId}`;
  }
  return `${error.message} Reference: ${error.correlationId}`;
}
