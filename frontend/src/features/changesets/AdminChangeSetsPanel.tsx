import { useEffect, useState } from 'react';

import {
  deleteAdminChangeSet,
  changeSetAction,
  loadAdminChangeSets,
  type ChangeSet,
} from '../../api/client';
import { ChangeSetDetails } from './ChangeSetPanel';
import { retryableChangeSet } from './changeSetRetry';
import {
  AppAlert as Alert,
  AppButton as Button,
  AppCard as Card,
  AppDialog as Dialog,
  AppEmptyState,
  AppGroup as Group,
  AppLoadingState,
  AppStatusBadge,
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
  const selected = items.find((item) => item.id === detailsId);

  const load = () => {
    setLoading(true);
    void loadAdminChangeSets()
      .then((rows) => {
        setItems(rows);
        setError('');
      })
      .catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : 'ChangeSets could not be loaded.');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const timer = window.setTimeout(load, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const remove = async (item: ChangeSet) => {
    if (!window.confirm(`Delete the ${item.state.toLowerCase()} ChangeSet “${item.title}”?`))
      return;
    setDeletingId(item.id);
    try {
      await deleteAdminChangeSet(item.id);
      setItems((current) => current.filter((row) => row.id !== item.id));
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : 'ChangeSet could not be deleted.');
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
      setError(reason instanceof Error ? reason.message : 'ChangeSet could not be executed.');
    } finally {
      setExecutingId('');
    }
  };

  const retry = async (item: ChangeSet) => {
    if (!item.active_group_id) return;
    if (
      !window.confirm(
        `Retry ${item.title}?\n\nCompleted provider operations will be reconciled and skipped safely.`,
      )
    )
      return;
    setRetryingId(item.id);
    setError('');
    try {
      const updated = await changeSetAction(item.id, item.active_group_id, 'retry');
      setItems((current) => current.map((row) => (row.id === updated.id ? updated : row)));
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : 'ChangeSet could not be retried.');
    } finally {
      setRetryingId('');
    }
  };

  if (loading) return <AppLoadingState label="Loading all ChangeSets" />;
  return (
    <Card>
      {error && (
        <Alert color="red" mb="md">
          {error}
        </Alert>
      )}
      {items.length === 0 ? (
        <AppEmptyState
          title="No ChangeSets"
          description="There are no ChangeSets in the organization."
        />
      ) : (
        <div className="fm-changeset-list" role="list" aria-label="All ChangeSets">
          {items.map((item) => (
            <div className="fm-changeset-row" role="listitem" key={item.id}>
              <div className="fm-changeset-main">
                <Text fw={650} className="fm-changeset-title">
                  {item.title}
                </Text>
                <Text size="xs" c="dimmed" className="fm-changeset-id">
                  {item.id}
                </Text>
              </div>
              <div>
                <AppStatusBadge value={item.state} />
              </div>
              <div className="fm-changeset-creator">
                <Text size="xs" c="dimmed">
                  CREATOR
                </Text>
                <Text size="sm">
                  {item.creator_display_name ?? item.creator_email ?? 'Unknown'}
                </Text>
              </div>
              <div className="fm-changeset-meta">
                <Text size="xs" c="dimmed">
                  {item.operations.length} operation{item.operations.length === 1 ? '' : 's'}
                </Text>
                <Text size="xs" c="dimmed">
                  Updated {new Date(item.updated_at).toLocaleString()}
                </Text>
              </div>
              <div className="fm-changeset-actions">
                <Group gap="xs" wrap="nowrap">
                  <Button size="xs" variant="subtle" onClick={() => setDetailsId(item.id)}>
                    View details
                  </Button>
                  {item.state === 'READY' && (
                    <Button
                      size="xs"
                      variant="light"
                      loading={executingId === item.id}
                      disabled={Boolean(executingId) || Boolean(deletingId)}
                      onClick={() => void execute(item)}
                    >
                      Execute
                    </Button>
                  )}
                  {DELETABLE_STATES.has(item.state) && (
                    <Button
                      size="xs"
                      color="red"
                      variant="light"
                      loading={deletingId === item.id}
                      disabled={Boolean(executingId)}
                      onClick={() => void remove(item)}
                    >
                      Delete
                    </Button>
                  )}
                  {retryableChangeSet(item) && (
                    <Button
                      size="xs"
                      variant="light"
                      loading={retryingId === item.id}
                      disabled={Boolean(executingId) || Boolean(deletingId) || Boolean(retryingId)}
                      onClick={() => void retry(item)}
                    >
                      Retry
                    </Button>
                  )}
                </Group>
              </div>
            </div>
          ))}
        </div>
      )}
      <Dialog
        opened={Boolean(selected)}
        onClose={() => setDetailsId('')}
        title="ChangeSet details"
        size="xl"
        centered
        closeButtonProps={{ 'aria-label': 'Close ChangeSet details' }}
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
