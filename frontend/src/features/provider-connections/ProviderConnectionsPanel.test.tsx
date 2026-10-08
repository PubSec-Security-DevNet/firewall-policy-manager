// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { MantineProvider } from '@mantine/core';
import axe from 'axe-core';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { appTheme } from '../../ui/theme';
import { ProviderConnectionsPanel } from './ProviderConnectionsPanel';

const guidance = {
  title: 'Dedicated FMC API service account',
  capability_target: 'READ-ONLY DISCOVERY',
  steps: ['Create a dedicated service identity.', 'Grant only verified read permissions.'],
  permission_note: 'Verify version-specific labels in the FMC API Explorer.',
  operations: [{ operation: 'policy read', method: 'GET', permission: 'Version-specific' }],
  official_references: [
    { label: 'Official Cisco documentation', url: 'https://www.cisco.com/example' },
  ],
};

afterEach(() => vi.restoreAllMocks());

describe('ProviderConnectionsPanel', () => {
  it('guides setup and clears restricted form state after saving', async () => {
    const requests: Array<{ path: string; body?: string }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const path =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        requests.push({ path, body: typeof init?.body === 'string' ? init.body : undefined });
        if (path.startsWith('/api/v1/admin/provider-connections?')) {
          return Promise.resolve(Response.json({ items: [], total: 0 }));
        }
        if (path.endsWith('/guidance/fmc')) return Promise.resolve(Response.json(guidance));
        if (path === '/api/v1/admin/provider-connections' && init?.method === 'POST') {
          return Promise.resolve(Response.json({}));
        }
        throw new Error(`Unexpected request: ${path}`);
      }),
    );
    const { container } = render(
      <MantineProvider theme={appTheme}>
        <ProviderConnectionsPanel />
      </MantineProvider>,
    );

    await userEvent.click(await screen.findByRole('button', { name: 'Add Connection' }));
    await waitFor(() => expect(screen.getByText(/How to create this credential/)).toBeVisible());
    expect(screen.getByText(/READ-ONLY DISCOVERY/)).toBeVisible();
    const user = userEvent.setup();
    await user.type(screen.getByRole('textbox', { name: 'Display name' }), 'FMC — Test');
    const endpoint = screen.getByRole('textbox', { name: 'FMC HTTPS URL' });
    await user.clear(endpoint);
    await user.type(endpoint, 'https://fmc.example.test');
    await user.type(screen.getByRole('textbox', { name: 'Dedicated API username' }), 'api-user');
    const password = document.querySelector<HTMLInputElement>('input[type="password"]');
    expect(password).not.toBeNull();
    if (!password) throw new Error('Password field was not rendered');
    await user.type(password, 'restricted-test-value');
    await user.click(screen.getByRole('button', { name: 'Save disabled connection' }));

    await waitFor(() => expect(password).toHaveValue(''));
    const createRequest = requests.find(
      (request) => request.path === '/api/v1/admin/provider-connections' && request.body,
    );
    expect(createRequest?.body).toContain('restricted-test-value');
    expect(JSON.stringify(window.sessionStorage)).not.toContain('restricted-test-value');
    expect(await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })).toEqual(
      expect.objectContaining({ violations: [] }),
    );
  }, 20_000);

  it('shows an untested-version warning without obsolete validation-write messaging', async () => {
    const warning =
      'FMC 10.1.x has not been write-tested with this application version. Production writes are allowed, but provider behavior should be monitored closely.';
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const path =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (path.startsWith('/api/v1/admin/provider-connections?')) {
          return Promise.resolve(
            Response.json({
              total: 1,
              items: [
                {
                  id: 'connection-1',
                  provider_type: 'fmc',
                  display_name: 'Production FMC',
                  lifecycle: 'ACTIVE',
                  enabled: true,
                  connection_mode: 'DIRECT',
                  evidence_profile: 'real',
                  base_endpoint: 'https://fmc.example.test',
                  region: null,
                  tls_mode: 'SYSTEM',
                  credential_present: true,
                  credential_type: 'USERNAME_PASSWORD',
                  credential_username: 'api-user',
                  credential_updated_at: '2026-09-20T00:00:00Z',
                  provider_version: '10.1.2 (build 3)',
                  connection_status: 'CONNECTED',
                  sync_status: 'COMPLETED',
                  last_connection_test: '2026-09-20T00:00:00Z',
                  last_successful_connection: '2026-09-20T00:00:00Z',
                  last_sync: '2026-09-20T00:00:00Z',
                  last_successful_sync: '2026-09-20T00:00:00Z',
                  last_error_code: null,
                  last_error_message: null,
                  last_error_correlation_id: null,
                  certificate_info: {},
                  sync_interval_minutes: 15,
                  write_enabled: false,
                  write_validation_mode: false,
                  version_family_tested: false,
                  compatibility_warning: warning,
                  write_enabled_at: null,
                  write_enabled_by_user_id: null,
                  scopes: [],
                  capability_evidence: [],
                  created_at: '2026-09-20T00:00:00Z',
                  updated_at: '2026-09-20T00:00:00Z',
                  revision: 1,
                },
              ],
            }),
          );
        }
        throw new Error(`Unexpected request: ${path}`);
      }),
    );

    render(
      <MantineProvider theme={appTheme}>
        <ProviderConnectionsPanel />
      </MantineProvider>,
    );

    expect(await screen.findByText('Version untested')).toBeVisible();
    expect(screen.getByText(warning)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Enable writes' })).toBeEnabled();
    expect(screen.queryByText(/validation writes/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/non-production/i)).not.toBeInTheDocument();
  });
});
