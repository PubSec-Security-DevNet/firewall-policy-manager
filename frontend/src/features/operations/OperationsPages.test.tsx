// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { MantineProvider } from '@mantine/core';
import axe from 'axe-core';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { appTheme } from '../../ui/theme';
import { AuditPage, explainDiscrepancy, resourceTypeLabel, SyncDriftPage } from './OperationsPages';

afterEach(() => vi.restoreAllMocks());

describe('operations pages', () => {
  it('uses the same human-readable resource labels for provider-only rows', () => {
    expect(resourceTypeLabel('access_rules')).toBe('Rule');
    expect(resourceTypeLabel('firewall_objects')).toBe('Object');
    expect(resourceTypeLabel('rule_categories')).toBe('Rule category');
    expect(resourceTypeLabel('new_provider_resource')).toBe('New Provider Resource');
  });

  it('describes only comparable provider changes from the application baseline', () => {
    const message = explainDiscrepancy({
      management_state: 'DRIFTED',
      kind: 'Rule',
      previous_snapshot: {
        application_snapshot: {
          position: 4,
          enabled: true,
          source_object_ids: ['object-1'],
        },
        source_object_ids: ['object-1'],
      },
      observed_snapshot: {
        position: 5,
        enabled: true,
      },
    });

    expect(message).toContain('Position');
    expect(message).not.toContain('Source Object Ids');
  });

  it('presents provider synchronization failures and drift without fabricating remediation', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const path =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (path.startsWith('/api/v1/firewall-managers'))
          return Promise.resolve(Response.json({ items: [], total: 0, next_cursor: null }));
        if (path.startsWith('/api/v1/policies'))
          return Promise.resolve(
            Response.json({
              items: [
                {
                  id: 'policy-1',
                  manager_id: 'manager-1',
                  name: 'Corporate Access',
                  provider_version: '1',
                  management_state: 'DRIFTED',
                  revision: 2,
                },
              ],
              total: 1,
              next_cursor: null,
            }),
          );
        if (path.startsWith('/api/v1/rules'))
          return Promise.resolve(Response.json({ items: [], total: 0, next_cursor: null }));
        if (path.startsWith('/api/v1/objects'))
          return Promise.resolve(Response.json({ items: [], total: 0, next_cursor: null }));
        if (path === '/api/v1/providers/status')
          return Promise.resolve(
            Response.json([
              {
                manager_id: 'manager-1',
                provider: 'fmc',
                display_name: 'Corporate FMC',
                provider_version: '7.6',
                capabilities: {},
                evidence_profile: 'real',
                writable: false,
                sync_status: 'FAILED',
                sync_complete: false,
                resources_seen: 0,
                last_sync_at: null,
                error_code: 'PROVIDER_UNAVAILABLE',
              },
            ]),
          );
        throw new Error(`Unexpected request: ${path}`);
      }),
    );
    render(
      <MantineProvider theme={appTheme}>
        <SyncDriftPage />
      </MantineProvider>,
    );
    expect(await screen.findByText('Corporate FMC')).toBeVisible();
    expect(screen.getByText('Corporate Access')).toBeVisible();
    const detailsButton = screen.getByRole('button', { name: 'View details' });
    expect(detailsButton).toBeVisible();
    await userEvent.click(detailsButton);
    expect(await screen.findByText('What this means')).toBeInTheDocument();
  });

  it('filters human-readable append-oriented audit evidence accessibly', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          Response.json({
            users: [],
            groups: [],
            policies: [],
            objects: [],
            zones: [],
            categories: [],
            memberships: [],
            policy_delegations: [],
            object_use_grants: [],
            zone_grants: [],
            ip_range_grants: [],
            object_create_grants: [],
            category_mappings: [],
            audit_events: [
              {
                id: 'event-1',
                actor: 'Platform Admin',
                acting_group: 'Finance',
                policy: 'Corporate Access',
                action: 'manage_grants',
                resource_type: 'policy',
                decision: 'ALLOW',
                reason_code: 'ALLOWED',
                interface: 'REST',
                correlation_id: 'request-1',
                details: { authorization_revision: 4, secret: 'must-not-render' },
                occurred_at: '2026-09-19T12:00:00Z',
              },
            ],
          }),
        ),
      ),
    );
    const { container } = render(
      <MantineProvider theme={appTheme}>
        <AuditPage />
      </MantineProvider>,
    );
    expect(await screen.findByText('Platform Admin')).toBeVisible();
    const user = userEvent.setup();
    await user.click(screen.getByText('View details'));
    expect(await screen.findByText(/Authorization Revision: 4/)).toBeInTheDocument();
    expect(screen.queryByText(/must-not-render/)).not.toBeInTheDocument();
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toHaveLength(0);
  });
});
