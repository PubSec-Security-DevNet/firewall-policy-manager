// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import type { AdministrationSnapshot } from '../../api/client';

const authorizationKeys: Record<string, string[]> = {
  memberships: ['user_id', 'group_id'],
  'policy-delegations': ['group_id', 'policy_id'],
  'object-use-grants': ['group_id', 'policy_id', 'object_id', 'permission'],
  'zone-grants': ['group_id', 'policy_id', 'zone_id', 'direction'],
  'ip-range-grants': ['group_id', 'policy_id', 'network'],
  'object-create-grants': ['group_id', 'policy_id', 'object_type'],
};

export function authorizationExpectedRevision(
  snapshot: AdministrationSnapshot,
  kind: string,
  payload: Record<string, unknown>,
): number | undefined {
  const rowsByKind: Record<string, Array<Record<string, unknown>>> = {
    memberships: snapshot.memberships,
    'policy-delegations': snapshot.policy_delegations,
    'object-use-grants': snapshot.object_use_grants,
    'zone-grants': snapshot.zone_grants,
    'ip-range-grants': snapshot.ip_range_grants,
    'object-create-grants': snapshot.object_create_grants,
  };
  const keys = authorizationKeys[kind];
  const row =
    kind === 'zone-grants' && payload.id
      ? rowsByKind[kind]?.find((candidate) => String(candidate.id) === String(payload.id))
      : rowsByKind[kind]?.find((candidate) =>
          keys?.every((key) => String(candidate[key]) === String(payload[key])),
        );
  const revision = Number(row?.revision);
  return Number.isInteger(revision) && revision >= 1 ? revision : undefined;
}

export function providerResourcesForPolicy(
  snapshot: AdministrationSnapshot,
  kind: string,
  policyId: string | null,
): Array<Record<string, unknown>> {
  if (!policyId) return [];
  const policy = snapshot.policies.find((candidate) => String(candidate.id) === policyId);
  if (!policy) return [];
  if (kind === 'object-use-grants') {
    return snapshot.objects.filter(
      (candidate) => String(candidate.manager_id) === String(policy.manager_id),
    );
  }
  if (kind === 'zone-grants') {
    return snapshot.zones.filter(
      (candidate) => String(candidate.manager_id) === String(policy.manager_id),
    );
  }
  return [];
}
