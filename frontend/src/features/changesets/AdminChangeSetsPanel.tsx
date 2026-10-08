// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';

import {
  deleteAdminChangeSet,
  changeSetAction,
  loadAdminChangeSets,
  type ChangeSet,
} from '../../api/client';
import { ChangeSetDetails, changeSetStatusLabel } from './ChangeSetPanel';
import { retryableChangeSet } from './changeSetRetry';
import { AdaptivePagination, useAdaptivePageSize } from '../shared/AdaptivePagination';
import {
  AppAlert as Alert,
  AppActionButton,
  AppDataTable,
  AppCard as Card,
  AppDialog as Dialog,
  AppEmptyState,
  AppGroup as Group,
  AppLoadingState,
  AppStatusBadge,
  AppTable as Table,
  AppText as Text,
} from '../../ui';

const DELETABLE_STATES = new Set(['DRAFT', 'VALIDATION_FAILED', 'READY']);

export function AdminChangeSetsPanel({ initialDetailsId }: { initialDetailsId?: string } = {}) {
  const [items, setItems] = useState<ChangeSet[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [deletingId, setDeletingId] = useState('');
  const [executingId, setExecutingId] = useState('');
  const [retryingId, setRetryingId] = useState('');
  const [detailsId, setDetailsId] = useState(initialDetailsId ?? '');
  const [page, setPage] = useState(1);
  const pageSize = useAdaptivePageSize();
  const selected = items.find((item) => item.id === detailsId);

  useEffect(() => {
    const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
    setPage((current) => Math.min(current, pageCount));
  }, [items.length, pageSize]);

  const load = () => {
    setLoading(true);
    void loadAdminChangeSets()
      .then((rows) => {
        setItems(rows);
        setError('');
      })
      .catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : 'Changesets could not be loaded.');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const timer = window.setTimeout(load, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const remove = async (item: ChangeSet) => {
    if (!window.confirm(`Delete the ${item.state.toLowerCase()} Changeset “${item.title}”?`))
      return;
    setDeletingId(item.id);
    try {
      await deleteAdminChangeSet(item.id);
      setItems((current) => current.filter((row) => row.id !== item.id));
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : 'Changeset could not be deleted.');
    } finally {
      setDeletingId('');
    }
  };

  const execute = async (item: ChangeSet) => {
    if (!item.active_group_id) return;
    if (!window.confirm(`Execute ${item.title}?\n\nThe validated operations will be queued.`))
      return;
    setExecutingId(item.id);
    setError('');
    try {
      const updated = await changeSetAction(item.id, item.active_group_id, 'execute');
      setItems((current) => current.map((row) => (row.id === updated.id ? updated : row)));
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : 'Changeset could not be executed.');
    } finally {
      setExecutingId('');
    }
  };

  const retry = async (item: ChangeSet) => {
    if (!item.active_group_id) return;
    const recovery = item.reconciliation_retry_available;
    if (
      !window.confirm(
        recovery
          ? `Recover ${item.title}?\n\nThe recorded provider success will be revalidated and the existing provider resource will be adopted without blindly repeating the write.`
          : `Retry ${item.title}?\n\nCompleted provider operations will be reconciled and skipped safely.`,
      )
    )
      return;
    setRetryingId(item.id);
    setError('');
    try {
      const updated = await changeSetAction(item.id, item.active_group_id, 'retry');
      setItems((current) => current.map((row) => (row.id === updated.id ? updated : row)));
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : 'Changeset could not be retried.');
    } finally {
      setRetryingId('');
    }
  };

  if (loading) return <AppLoadingState label="Loading all Changesets" />;
  return (
    <Card>
      {error && (
        <Alert color="red" mb="md">
          {error}
        </Alert>
      )}
      {items.length === 0 ? (
        <AppEmptyState
          title="No Changesets"
          description="There are no Changesets in the organization."
        />
      ) : (
        <div className="fm-changeset-table">
          <AppDataTable label="All Changesets">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Changeset</Table.Th>
                <Table.Th>Operations</Table.Th>
                <Table.Th>Creator</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Updated</Table.Th>
                <Table.Th>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.slice((page - 1) * pageSize, page * pageSize).map((item) => (
                <Table.Tr key={item.id}>
                  <Table.Td>
                    <Text fw={650}>{item.title}</Text>
                    <Text size="xs" c="dimmed" className="fm-code">
                      {item.id}
                    </Text>
                  </Table.Td>
                  <Table.Td>{item.operations.length}</Table.Td>
                  <Table.Td>
                    {item.creator_display_name ?? item.creator_email ?? 'Unknown'}
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
                      {(!item.approval_required && item.state === 'READY') ||
                      (item.approval_required && item.state === 'APPROVED') ? (
                        <AppActionButton
                          intent="secondary"
                          loading={executingId === item.id}
                          disabled={Boolean(executingId) || Boolean(deletingId)}
                          onClick={() => void execute(item)}
                        >
                          Execute
                        </AppActionButton>
                      ) : null}
                      {DELETABLE_STATES.has(item.state) && (
                        <AppActionButton
                          intent="quiet-danger"
                          loading={deletingId === item.id}
                          disabled={Boolean(executingId)}
                          onClick={() => void remove(item)}
                        >
                          Delete
                        </AppActionButton>
                      )}
                      {retryableChangeSet(item) && (
                        <AppActionButton
                          intent="secondary"
                          loading={retryingId === item.id}
                          disabled={
                            Boolean(executingId) || Boolean(deletingId) || Boolean(retryingId)
                          }
                          onClick={() => void retry(item)}
                        >
                          {item.reconciliation_retry_available ? 'Recover' : 'Retry'}
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
        {selected && <ChangeSetDetails item={selected} />}
      </Dialog>
    </Card>
  );
}
