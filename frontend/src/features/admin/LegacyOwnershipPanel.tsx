// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';
import {
  confirmLegacyOwnership,
  loadLegacyOwnership,
  type LegacyOwnershipReview,
} from '../../api/client';
import {
  AppAlert,
  AppButton,
  AppCard,
  AppDialog,
  AppErrorState,
  AppStack,
  AppText,
  AppTextarea,
} from '../../ui';

export function LegacyOwnershipPanel() {
  const [items, setItems] = useState<LegacyOwnershipReview[]>([]);
  const [selected, setSelected] = useState<LegacyOwnershipReview>();
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string>();
  const [saving, setSaving] = useState(false);
  const refresh = () =>
    loadLegacyOwnership()
      .then(setItems)
      .catch((e: unknown) => setError(String(e)));
  useEffect(() => {
    void refresh();
  }, []);
  const confirm = async () => {
    if (!selected || saving) return;
    setSaving(true);
    try {
      await confirmLegacyOwnership(selected, reason);
      setSelected(undefined);
      setReason('');
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };
  if (!items.length && !error) return null;
  return (
    <AppCard>
      <AppStack>
        <AppText fw={600}>Legacy ownership review</AppText>
        <AppAlert color="yellow">
          These preserved assignments require individual administrator review. Their Group and
          policy remain restricted until every pending assignment in that scope is confirmed.
          Confirmation does not re-enable provider writes or revive old approvals.
        </AppAlert>
        {error && <AppErrorState message={error} />}
        {items.map((item) => (
          <AppCard key={item.id}>
            <AppStack gap="xs">
              <AppText>
                {item.name} — {item.resource_type} — Review required
              </AppText>
              <AppText size="sm">
                Resource {item.resource_id} · Group {item.group_id} · Policy{' '}
                {item.policy_id ?? 'Unassigned'}
              </AppText>
              <AppButton
                disabled={!item.policy_id || !item.resource_revision}
                onClick={() => {
                  setSelected(item);
                  setReason('');
                }}
              >
                Review assignment
              </AppButton>
            </AppStack>
          </AppCard>
        ))}
        <AppDialog
          opened={!!selected}
          onClose={() => !saving && setSelected(undefined)}
          title="Confirm one legacy assignment"
        >
          <AppStack>
            <AppText>
              Confirm {selected?.name} ({selected?.resource_type}) for Group {selected?.group_id},
              policy {selected?.policy_id}. Verify the resource and intended authority independently
              of its name.
            </AppText>
            <AppTextarea
              label="Review evidence and reason"
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
              minRows={3}
            />
            <AppButton
              loading={saving}
              disabled={reason.trim().length < 10}
              onClick={() => void confirm()}
            >
              Confirm this assignment
            </AppButton>
          </AppStack>
        </AppDialog>
      </AppStack>
    </AppCard>
  );
}
