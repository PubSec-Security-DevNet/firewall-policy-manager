import { useEffect, useState } from 'react';

import {
  approveChangeSet,
  loadPendingApprovals,
  rejectChangeSet,
  type ChangeSet,
} from '../../api/client';
import {
  AppActionButton,
  AppButton,
  AppCard,
  AppDataTable,
  AppDialog,
  AppEmptyState,
  AppErrorState,
  AppGroup,
  AppLoadingState,
  AppPage,
  AppStack,
  AppTextarea,
  AppTable,
  AppText,
} from '../../ui';

function approvalPayload(payload: Record<string, unknown>) {
  return Object.fromEntries(
    Object.entries(payload).filter(([key, value]) => {
      if (key === 'mock_behavior') return false;
      if (key === 'member_object_ids' && Array.isArray(value) && value.length === 0) return false;
      return true;
    }),
  );
}

export function ApprovalsPage() {
  const [items, setItems] = useState<ChangeSet[] | null>(null);
  const [error, setError] = useState<string>();
  const [saving, setSaving] = useState<string>();
  const [rejecting, setRejecting] = useState<ChangeSet>();
  const [details, setDetails] = useState<ChangeSet>();
  const [reason, setReason] = useState('');
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
      setError(reason instanceof Error ? reason.message : 'Changeset approval failed.');
    } finally {
      setSaving(undefined);
    }
  };
  const reject = async () => {
    if (!rejecting || !reason.trim()) return;
    setSaving(rejecting.id);
    setError(undefined);
    try {
      await rejectChangeSet(rejecting.id, rejecting.active_group_id, reason.trim());
      setRejecting(undefined);
      setReason('');
      await refresh();
    } catch (reasonValue) {
      setError(reasonValue instanceof Error ? reasonValue.message : 'Changeset rejection failed.');
    } finally {
      setSaving(undefined);
    }
  };
  return (
    <AppPage
      eyebrow="Operations"
      title="Pending approvals"
      description="Review and approve validated Changesets submitted by members of approval-controlled Groups."
    >
      <AppDialog
        opened={Boolean(rejecting)}
        onClose={() => {
          if (!saving) {
            setRejecting(undefined);
            setReason('');
          }
        }}
        title="Reject Changeset"
        centered
      >
        <AppText size="sm" c="dimmed" mb="md">
          The Changeset will not be applied. The submitter will see this rejection and reason and
          can create a corrected submission.
        </AppText>
        <AppTextarea
          label="Reason for rejection"
          placeholder="Explain what must be corrected before resubmission."
          minRows={5}
          value={reason}
          onChange={(event) => setReason(event.currentTarget.value)}
          disabled={Boolean(saving)}
          required
        />
        <AppGroup justify="flex-end" mt="md">
          <AppButton
            variant="subtle"
            onClick={() => {
              setRejecting(undefined);
              setReason('');
            }}
            disabled={Boolean(saving)}
          >
            Cancel
          </AppButton>
          <AppButton
            color="red"
            loading={Boolean(saving)}
            disabled={!reason.trim()}
            onClick={() => void reject()}
          >
            Reject Changeset
          </AppButton>
        </AppGroup>
      </AppDialog>
      <AppDialog
        opened={Boolean(details)}
        onClose={() => setDetails(undefined)}
        title={details ? `Approval details · ${details.title}` : 'Approval details'}
        centered
        size="lg"
      >
        {details && (
          <AppStack gap="md">
            <AppText size="sm" c="dimmed">
              Exact requested operations for {details.active_group_name ?? 'Unknown group'}. Review
              the provider payload before approving this Changeset.
            </AppText>
            {details.operations.map((operation, index) => (
              <AppCard key={operation.id} withBorder p="md">
                <AppText fw={700} mb={4}>
                  {index + 1}. {operation.kind.replaceAll('_', ' ')}
                </AppText>
                <AppText size="xs" c="dimmed" mb="sm">
                  Requested operation payload
                </AppText>
                <pre
                  style={{
                    margin: 0,
                    padding: 12,
                    overflowX: 'auto',
                    borderRadius: 8,
                    background: '#091722',
                    color: '#d7e8f2',
                    fontSize: 12,
                    lineHeight: 1.5,
                  }}
                >
                  {JSON.stringify(approvalPayload(operation.payload), null, 2)}
                </pre>
              </AppCard>
            ))}
            <AppGroup justify="flex-end">
              <AppButton onClick={() => setDetails(undefined)}>Close</AppButton>
            </AppGroup>
          </AppStack>
        )}
      </AppDialog>
      {error && <AppErrorState message={error} />}
      {!error && !items && <AppLoadingState label="Loading pending approvals" />}
      {!error && items?.length === 0 && (
        <AppEmptyState title="No pending approvals" description="You are up to date." />
      )}
      {items && items.length > 0 && (
        <AppDataTable label="Pending approvals">
          <AppTable.Thead>
            <AppTable.Tr>
              <AppTable.Th>Changeset</AppTable.Th>
              <AppTable.Th>Submitted by</AppTable.Th>
              <AppTable.Th>Group</AppTable.Th>
              <AppTable.Th>Actions</AppTable.Th>
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
                <AppTable.Td>{item.active_group_name ?? 'Unknown group'}</AppTable.Td>
                <AppTable.Td>
                  <AppGroup gap="xs" wrap="nowrap">
                    <AppActionButton onClick={() => setDetails(item)}>View details</AppActionButton>
                    <AppActionButton
                      loading={saving === item.id}
                      onClick={() => void approve(item)}
                    >
                      Approve
                    </AppActionButton>
                    <AppActionButton
                      intent="danger"
                      disabled={Boolean(saving)}
                      onClick={() => {
                        setRejecting(item);
                        setReason('');
                      }}
                    >
                      Reject
                    </AppActionButton>
                  </AppGroup>
                </AppTable.Td>
              </AppTable.Tr>
            ))}
          </AppTable.Tbody>
        </AppDataTable>
      )}
    </AppPage>
  );
}
