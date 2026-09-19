import { MantineProvider } from '@mantine/core';
import axe from 'axe-core';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { appTheme } from '../../ui/theme';
import { OverviewPage } from './OverviewPage';

const finance = '20000000-0000-0000-0000-000000000001';
const engineering = '20000000-0000-0000-0000-000000000002';
const policy = '50000000-0000-0000-0000-000000000001';

const overview = {
  organization: 'Example Organization',
  counts: { managers: 2, policies: 1, rules: 2, objects: 9, change_sets: 1 },
  providers: [
    {
      provider: 'fmc',
      display_name: 'Local FMC Mock',
      provider_version: 'mock-fmc-1.0',
      policy_count: 1,
      object_count: 9,
      writable: false,
    },
  ],
};

function session(
  groups = [{ id: finance, name: 'Finance', provider_slug: 'FINANCE', revision: 1 }],
) {
  return {
    authentication_mode: 'development',
    user_id: '30000000-0000-0000-0000-000000000001',
    email: 'viewer@example.test',
    role: 'viewer',
    groups,
  };
}

function delegatedContext(groupId: string) {
  const isFinance = groupId === finance;
  return {
    policy: {
      id: policy,
      manager_id: '40000000-0000-0000-0000-000000000001',
      name: 'Corporate-ACP',
      management_state: 'OBSERVED',
      revision: 1,
    },
    capabilities: isFinance ? ['view', 'create_rule'] : ['view', 'reorder_rule'],
    rules: [],
    objects: [
      {
        id: isFinance
          ? '60000000-0000-0000-0000-000000000001'
          : '60000000-0000-0000-0000-000000000002',
        name: isFinance ? 'FINANCE-SERVERS' : 'ENG-SERVERS',
        object_type: 'NETWORK',
      },
    ],
    zones: [
      {
        id: isFinance
          ? '70000000-0000-0000-0000-000000000001'
          : '70000000-0000-0000-0000-000000000002',
        name: isFinance ? 'Inside-Finance' : 'Inside-Engineering',
        direction: 'BOTH',
      },
    ],
    categories: [
      {
        id: isFinance
          ? '51000000-0000-0000-0000-000000000001'
          : '51000000-0000-0000-0000-000000000002',
        name: isFinance ? 'FINANCE__RULES' : 'ENGINEERING__RULES',
      },
    ],
    ip_ranges: [isFinance ? '10.20.0.0/16' : '172.16.0.0/12'],
    object_create: [{ object_type: 'NETWORK', provider_supported: false }],
  };
}

function installFetch(currentSession = session()) {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const path =
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (path === '/api/v1/session') return Promise.resolve(Response.json(currentSession));
      if (path === '/api/v1/overview') return Promise.resolve(Response.json(overview));
      if (path.startsWith('/api/v1/delegated/policies')) {
        return Promise.resolve(
          Response.json([
            {
              id: policy,
              manager_id: '40000000-0000-0000-0000-000000000001',
              name: 'Corporate-ACP',
              management_state: 'OBSERVED',
              revision: 1,
            },
          ]),
        );
      }
      if (path.startsWith('/api/v1/delegated/context')) {
        const groupId = new URL(path, 'http://localhost').searchParams.get('active_group_id') ?? '';
        return Promise.resolve(Response.json(delegatedContext(groupId)));
      }
      if (path.startsWith('/api/v1/changesets')) {
        return Promise.resolve(Response.json([]));
      }
      throw new Error(`Unexpected request: ${path}`);
    }),
  );
}

afterEach(() => vi.restoreAllMocks());

describe('OverviewPage', () => {
  it('renders the selected Group policy and only its entitlements accessibly', async () => {
    installFetch();
    const { container } = render(
      <MantineProvider theme={appTheme}>
        <OverviewPage />
      </MantineProvider>,
    );
    expect(await screen.findByText('FINANCE-SERVERS')).toBeVisible();
    expect(screen.getByText('Inside-Finance')).toBeVisible();
    expect(screen.getByText('10.20.0.0/16')).toBeVisible();
    expect(screen.queryByText('ENG-SERVERS')).not.toBeInTheDocument();
    expect(screen.getByText(/Working as: Finance/)).toBeVisible();
    expect(screen.getByText('Mock execution only')).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Draft ChangeSets' })).toBeVisible();
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    });
    expect(results.violations).toHaveLength(0);
  });

  it('clears prior entitlements and reloads when active Group changes', async () => {
    installFetch(
      session([
        { id: finance, name: 'Finance', provider_slug: 'FINANCE', revision: 1 },
        { id: engineering, name: 'Engineering', provider_slug: 'ENGINEERING', revision: 1 },
      ]),
    );
    render(
      <MantineProvider theme={appTheme}>
        <OverviewPage />
      </MantineProvider>,
    );
    await screen.findByRole('heading', { name: 'Example Organization' });
    const user = userEvent.setup();
    await user.click(screen.getByRole('textbox', { name: 'Working as' }));
    await user.click(screen.getByText('Finance', { selector: '[role="option"] span' }));
    expect(await screen.findByText('FINANCE-SERVERS')).toBeVisible();
    await user.click(screen.getByRole('textbox', { name: 'Working as' }));
    await user.click(screen.getByText('Engineering', { selector: '[role="option"] span' }));
    expect(await screen.findByText('ENG-SERVERS')).toBeVisible();
    expect(screen.queryByText('FINANCE-SERVERS')).not.toBeInTheDocument();
    expect(screen.queryByText('10.20.0.0/16')).not.toBeInTheDocument();
    const changeSetRequests = vi
      .mocked(fetch)
      .mock.calls.map(([input]) =>
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      )
      .filter((path) => path.startsWith('/api/v1/changesets'));
    expect(changeSetRequests.some((path) => path.includes(finance))).toBe(true);
    expect(changeSetRequests.some((path) => path.includes(engineering))).toBe(true);
  });

  it('keeps delegated features unavailable when the User has no Group', async () => {
    installFetch(session([]));
    render(
      <MantineProvider theme={appTheme}>
        <OverviewPage />
      </MantineProvider>,
    );
    expect(await screen.findByText(/do not have an enabled Group membership/i)).toBeVisible();
  });

  it('announces loading while the initial API requests are pending', () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => new Promise<Response>(() => undefined)),
    );
    render(
      <MantineProvider theme={appTheme}>
        <OverviewPage />
      </MantineProvider>,
    );
    expect(screen.getByRole('status')).toHaveTextContent('Loading inventory');
  });

  it('renders a safe API error with its correlation reference', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          Response.json(
            {
              error: {
                code: 'NOT_AUTHENTICATED',
                message: 'Authentication is required.',
                details: {},
                correlation_id: 'request-123',
              },
            },
            { status: 401 },
          ),
        ),
      ),
    );
    render(
      <MantineProvider theme={appTheme}>
        <OverviewPage />
      </MantineProvider>,
    );
    await waitFor(() => expect(screen.getByText(/Reference: request-123/)).toBeVisible());
  });
});
