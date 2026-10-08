// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import type { AdministrationSnapshot } from '../../api/client';
import { authorizationExpectedRevision, providerResourcesForPolicy } from './authorizationRevision';

function snapshot(): AdministrationSnapshot {
  return {
    users: [],
    groups: [],
    policies: [
      { id: 'policy-1', manager_id: 'manager-1', name: 'FMC policy' },
      { id: 'policy-2', manager_id: 'manager-2', name: 'SCC policy' },
    ],
    objects: [
      { id: 'object-1', manager_id: 'manager-1', name: 'FMC object' },
      { id: 'object-2', manager_id: 'manager-2', name: 'SCC object' },
    ],
    zones: [
      { id: 'zone-1', manager_id: 'manager-1', name: 'FMC zone' },
      { id: 'zone-2', manager_id: 'manager-2', name: 'SCC zone' },
    ],
    categories: [
      { id: 'category-1', policy_id: 'policy-1', name: 'FMC category' },
      { id: 'category-2', policy_id: 'policy-2', name: 'SCC category' },
    ],
    memberships: [],
    policy_delegations: [
      {
        id: 'delegation-1',
        group_id: 'group-1',
        policy_id: 'policy-1',
        capabilities: ['view'],
        is_active: true,
        revision: 4,
      },
    ],
    object_use_grants: [],
    zone_grants: [],
    ip_range_grants: [],
    object_create_grants: [],
  };
}

describe('authorizationExpectedRevision', () => {
  it('uses the current logical grant revision when updating a policy delegation', () => {
    expect(
      authorizationExpectedRevision(snapshot(), 'policy-delegations', {
        group_id: 'group-1',
        policy_id: 'policy-1',
        capabilities: ['view', 'create_rule'],
      }),
    ).toBe(4);
  });

  it('omits expected_revision when creating a new logical grant', () => {
    expect(
      authorizationExpectedRevision(snapshot(), 'policy-delegations', {
        group_id: 'group-1',
        policy_id: 'policy-2',
        capabilities: ['view'],
      }),
    ).toBeUndefined();
  });

  it('only offers provider resources attached to the selected policy manager', () => {
    expect(
      providerResourcesForPolicy(snapshot(), 'object-use-grants', 'policy-2').map(
        (item) => item.id,
      ),
    ).toEqual(['object-2']);
    expect(
      providerResourcesForPolicy(snapshot(), 'zone-grants', 'policy-1').map((item) => item.id),
    ).toEqual(['zone-1']);
  });
});
