import { useEffect, useState } from 'react';

import { approveChangeSet, loadPendingApprovals, type ChangeSet } from '../../api/client';
import {
  AppActionButton,
  AppDataTable,
  AppEmptyState,
  AppErrorState,
  AppLoadingState,
  AppPage,
  AppStatusBadge,
  AppTable,
  AppText,
} from '../../ui';

export function ApprovalsPage() {
  const [items, setItems] = useState<ChangeSet[] | null>(null);
  const [error, setError] = useState<string>();
  const [saving, setSaving] = useState<string>();
  const refresh = () =>
    loadPendingApprovals()
      .then((result) => setItems(result.items))
      .catch((reason: unknown) =>
        setError(reason instanceof Error ? reason.message : 'Approvals could not be loaded.'),
      );
  useEffect(() => {
    void refresh();
  }, []);
  const approve = async (item: ChangeSet) => {
    setSaving(item.id);
    setError(undefined);
    try {
      await approveChangeSet(item.id, item.active_group_id);
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'ChangeSet approval failed.');
    } finally {
      setSaving(undefined);
    }
  };
  return (
    <AppPage
      eyebrow="Operations"
      title="Pending approvals"
      description="Review and approve validated ChangeSets submitted by members of approval-controlled Groups."
    >
      {error && <AppErrorState message={error} />}
      {!error && !items && <AppLoadingState label="Loading pending approvals" />}
      {!error && items?.length === 0 && (
        <AppEmptyState title="No pending approvals" description="You are up to date." />
      )}
      {items && items.length > 0 && (
        <AppDataTable label="Pending approvals">
          <AppTable.Thead>
            <AppTable.Tr>
              <AppTable.Th>ChangeSet</AppTable.Th>
              <AppTable.Th>Submitted by</AppTable.Th>
              <AppTable.Th>Group</AppTable.Th>
              <AppTable.Th>Status</AppTable.Th>
              <AppTable.Th>Action</AppTable.Th>
            </AppTable.Tr>
          </AppTable.Thead>
          <AppTable.Tbody>
            {items.map((item) => (
              <AppTable.Tr key={item.id}>
                <AppTable.Td>
                  <AppText fw={650}>{item.title}</AppText>
                  <AppText size="xs" c="dimmed">
                    {item.operations.length} operation(s)
                  </AppText>
                </AppTable.Td>
                <AppTable.Td>
                  {item.creator_display_name ?? item.creator_email ?? item.creator_id}
                </AppTable.Td>
                <AppTable.Td>{item.active_group_id}</AppTable.Td>
                <AppTable.Td>
                  <AppStatusBadge value={item.state} />
                </AppTable.Td>
                <AppTable.Td>
                  <AppActionButton loading={saving === item.id} onClick={() => void approve(item)}>
                    Approve
                  </AppActionButton>
                </AppTable.Td>
              </AppTable.Tr>
            ))}
          </AppTable.Tbody>
        </AppDataTable>
      )}
    </AppPage>
  );
}
