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

    expect(await screen.findByText(/How to create this credential/)).toBeVisible();
    expect(screen.getByText(/READ-ONLY DISCOVERY/)).toBeVisible();
    const user = userEvent.setup();
    await user.type(screen.getByRole('textbox', { name: 'Display name' }), 'FMC — Test');
    const endpoint = screen.getByRole('textbox', { name: 'FMC HTTPS URL' });
    await user.clear(endpoint);
    await user.type(endpoint, 'https://fmc.example.test');
    await user.type(screen.getByRole('textbox', { name: 'Dedicated API username' }), 'api-user');
    const password = container.querySelector<HTMLInputElement>('input[type="password"]');
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
  });
});
