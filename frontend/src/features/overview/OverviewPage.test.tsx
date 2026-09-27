import { MantineProvider } from '@mantine/core';
import axe from 'axe-core';
import { render, screen, waitFor, within } from '@testing-library/react';
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

const administration = {
  users: [
    {
      id: 'user-1',
      display_name: 'Alice Admin',
      email: 'admin@example.test',
      role: 'admin',
      enabled: true,
      revision: 1,
    },
  ],
  groups: [
    { id: finance, name: 'Finance', provider_slug: 'FINANCE', enabled: true, revision: 1 },
    {
      id: 'group-datacenter',
      name: 'Datacenter',
      provider_slug: 'DATACENTER',
      enabled: true,
      revision: 1,
    },
  ],
  policies: [{ id: policy, manager_id: 'manager-1', name: 'Corporate-ACP' }],
  objects: [],
  zones: [],
  categories: [],
  memberships: [
    { id: 'membership-1', user_id: 'user-1', group_id: finance, status: 'ACTIVE', revision: 1 },
  ],
  policy_delegations: [
    {
      id: 'delegation-1',
      group_id: finance,
      policy_id: policy,
      capabilities: ['view', 'modify_rule'],
      is_active: true,
      revision: 2,
    },
  ],
  direct_user_policy_grants: [],
  object_use_grants: [],
  zone_grants: [],
  ip_range_grants: [],
  object_create_grants: [],
  category_mappings: [],
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
    provider_is_mock: true,
    provider_name: 'Local FMC Mock',
    provider_type: 'fmc',
    provider_writable: true,
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
    object_create: [{ object_type: 'NETWORK', provider_supported: true }],
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
      if (path === '/api/v1/admin/authorization') {
        return Promise.resolve(Response.json(administration));
      }
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
    const user = userEvent.setup();
    await user.click(
      within(await screen.findByRole('navigation', { name: 'Primary navigation' })).getByRole(
        'button',
        {
          name: 'Objects',
        },
      ),
    );
    expect(await screen.findByText('FINANCE-SERVERS')).toBeVisible();
    expect(screen.queryByText('ENG-SERVERS')).not.toBeInTheDocument();
    expect(document.querySelector('.fm-working-context-value')).toHaveTextContent('Finance');
    await user.click(screen.getByRole('button', { name: 'Create object' }));
    await waitFor(() =>
      expect(screen.getByRole('dialog', { name: 'Create firewall object' })).toBeVisible(),
    );
    expect(screen.getByRole('heading', { name: 'Object inventory' })).toBeVisible();
    expect(screen.getByText(/IPv4 or IPv6 host, CIDR subnet, or IP range/)).toBeVisible();
    expect(document.querySelector('.mantine-Modal-body')).toHaveClass('fm-object-dialog-body');
    await user.type(screen.getByRole('textbox', { name: 'Object name' }), 'web-one');
    await user.type(screen.getByRole('textbox', { name: 'Value' }), '10.20.10.1');
    await user.click(screen.getByRole('button', { name: 'Add object to ChangeSet' }));
    await user.type(screen.getByRole('textbox', { name: 'Object name' }), 'web-two');
    await user.type(screen.getByRole('textbox', { name: 'Value' }), '10.20.10.2');
    await user.click(screen.getByRole('button', { name: 'Add object to ChangeSet' }));
    expect(screen.getByRole('button', { name: 'Review 2 objects' })).toBeEnabled();
    expect(screen.getByRole('region', { name: 'Objects in this ChangeSet' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(document.querySelectorAll('.mantine-Modal-header')).toHaveLength(0));
    await user.click(
      within(screen.getByRole('navigation', { name: 'Primary navigation' })).getByRole('button', {
        name: 'Policies',
      }),
    );
    expect(screen.getByText('10.20.0.0/16')).toBeVisible();
    await user.click(
      within(screen.getByRole('navigation', { name: 'Primary navigation' })).getByRole('button', {
        name: 'Changes',
      }),
    );
    expect(screen.getByRole('heading', { name: 'Submitted ChangeSets' })).toBeVisible();
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    });
    expect(results.violations, JSON.stringify(results.violations, null, 2)).toHaveLength(0);
  }, 20_000);

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
    const user = userEvent.setup();
    await user.click(
      within(await screen.findByRole('navigation', { name: 'Primary navigation' })).getByRole(
        'button',
        {
          name: 'Objects',
        },
      ),
    );
    expect(await screen.findByText('FINANCE-SERVERS')).toBeVisible();
    await user.click(
      within(screen.getByRole('navigation', { name: 'Primary navigation' })).getByRole('button', {
        name: 'Policies',
      }),
    );
    const engineeringMapping = await screen.findByRole('row', {
      name: /Engineering Corporate-ACP/,
    });
    await user.click(within(engineeringMapping).getByRole('button', { name: 'Select' }));
    await user.click(
      within(screen.getByRole('navigation', { name: 'Primary navigation' })).getByRole('button', {
        name: 'Objects',
      }),
    );
    expect(await screen.findByText('ENG-SERVERS')).toBeVisible();
    expect(screen.queryByText('FINANCE-SERVERS')).not.toBeInTheDocument();
    expect(screen.queryByText('10.20.0.0/16')).not.toBeInTheDocument();
    const contextRequests = vi
      .mocked(fetch)
      .mock.calls.map(([input]) =>
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      )
      .filter((path) => path.startsWith('/api/v1/delegated/context'));
    expect(contextRequests.some((path) => path.includes(finance))).toBe(true);
    expect(contextRequests.some((path) => path.includes(engineering))).toBe(true);
  }, 20_000);

  it('keeps delegated features unavailable when the User has no Group', async () => {
    installFetch(session([]));
    render(
      <MantineProvider theme={appTheme}>
        <OverviewPage />
      </MantineProvider>,
    );
    await userEvent.setup().click(
      within(await screen.findByRole('navigation', { name: 'Primary navigation' })).getByRole(
        'button',
        {
          name: 'Rules',
        },
      ),
    );
    expect(await screen.findByText(/do not have an enabled Group membership/i)).toBeVisible();
  }, 20_000);

  it('renders Groups, Users, and Access grants as separate management pages', async () => {
    installFetch({ ...session(), role: 'admin' });
    const { container } = render(
      <MantineProvider theme={appTheme}>
        <OverviewPage />
      </MantineProvider>,
    );
    const user = userEvent.setup();
    const navigation = within(
      await screen.findByRole('navigation', { name: 'Primary navigation' }),
    );
    const navigationLabels = navigation
      .getAllByRole('button')
      .map((button) => button.textContent?.trim());
    expect(navigationLabels.indexOf('Users')).toBeLessThan(navigationLabels.indexOf('Groups'));

    await user.click(navigation.getByRole('button', { name: 'Groups' }));
    expect(
      await screen.findByRole('button', { name: 'Create Group' }, { timeout: 5_000 }),
    ).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Create User' })).not.toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: 'Manage members' })[0]!);
    const memberDialog = await screen.findByRole('dialog', { name: 'Manage members' });
    await waitFor(() => expect(memberDialog).toBeVisible());
    expect(within(memberDialog).getByText('Alice Admin')).toBeVisible();
    expect(within(memberDialog).getByRole('button', { name: 'Remove' })).toBeVisible();
    await user.click(within(memberDialog).getByRole('button', { name: 'Close' }));

    await user.click(navigation.getByRole('button', { name: 'Users' }));
    expect(await screen.findByRole('button', { name: 'Create User' })).toBeVisible();
    expect(screen.getAllByText('1 group').length).toBeGreaterThan(0);
    await user.click(screen.getByRole('button', { name: 'Manage Groups' }));
    const groupDialog = await screen.findByRole('dialog', { name: 'Manage Groups' });
    await waitFor(() => expect(groupDialog).toBeVisible());
    expect(within(groupDialog).getByRole('button', { name: 'Remove' })).toBeVisible();
    await user.click(within(groupDialog).getByRole('textbox', { name: 'Filter memberships' }));
    await user.keyboard('{ArrowDown}{ArrowDown}{Enter}');
    expect(within(groupDialog).getByText('Datacenter')).toBeVisible();
    expect(within(groupDialog).queryByText('Finance')).not.toBeInTheDocument();
    await user.click(within(groupDialog).getByRole('textbox', { name: 'Filter memberships' }));
    await user.keyboard('{ArrowUp}{ArrowUp}{Enter}');
    await user.click(within(groupDialog).getByRole('textbox', { name: 'Sort memberships' }));
    await user.keyboard('{ArrowDown}{ArrowDown}{Enter}');
    expect(groupDialog.querySelector('.fm-membership-row')).toHaveTextContent('Datacenter');
    await user.click(within(groupDialog).getByRole('button', { name: 'Close' }));

    await user.click(navigation.getByRole('button', { name: 'Access grants' }));
    const addGrant = await screen.findByRole('button', { name: 'Add group delegation' });
    expect(screen.getByRole('textbox', { name: 'Search access grants' })).toBeVisible();
    expect(screen.getByRole('textbox', { name: 'Sort access grants' })).toHaveValue('Sort: A–Z');
    expect(screen.getByRole('tab', { name: 'Policy access' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Create User' })).not.toBeInTheDocument();
    await user.click(addGrant);
    await waitFor(() =>
      expect(screen.getByRole('dialog', { name: 'Add group policy delegation' })).toBeVisible(),
    );
    expect(screen.getByRole('textbox', { name: 'Authorization record' })).toBeVisible();
    await user.click(
      within(screen.getByRole('dialog', { name: 'Add group policy delegation' })).getByRole(
        'button',
        { name: 'Close' },
      ),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'Add group policy delegation' }),
      ).not.toBeInTheDocument(),
    );
    await user.click(screen.getByRole('tab', { name: 'Resource access' }));
    expect(screen.getByRole('heading', { name: 'Network objects' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Add network object access' }));
    const networkGrantDialog = await screen.findByRole('dialog', {
      name: 'Add network object access',
    });
    expect(
      within(networkGrantDialog).getByRole('textbox', { name: 'Object permission' }),
    ).toHaveValue('Use in policy rules');
    await user.click(within(networkGrantDialog).getByRole('button', { name: 'Close' }));
    await user.click(screen.getByRole('tab', { name: 'Ports' }));
    expect(screen.getByRole('heading', { name: 'Port objects' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Add port object access' })).toBeVisible();
    await user.click(screen.getByRole('tab', { name: 'URLs' }));
    expect(screen.getByRole('heading', { name: 'URL objects' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Add URL object access' })).toBeVisible();
    await user.click(screen.getByRole('tab', { name: 'Policy access' }));
    await user.click(screen.getByRole('button', { name: 'Modify' }));
    const editGrantDialog = await screen.findByRole('dialog', { name: 'Modify access grant' });
    await waitFor(() => expect(editGrantDialog).toBeVisible());
    expect(within(editGrantDialog).getByText('View policy')).toBeVisible();
    expect(within(editGrantDialog).getByText('Modify rules')).toBeVisible();
    await user.click(within(editGrantDialog).getByRole('button', { name: 'Close' }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Modify access grant' })).not.toBeInTheDocument(),
    );
    await waitFor(() => expect(document.querySelectorAll('.mantine-Modal-header')).toHaveLength(0));
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    });
    expect(results.violations, JSON.stringify(results.violations, null, 2)).toHaveLength(0);
  }, 20_000);

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
    expect(screen.getByRole('status')).toHaveTextContent('Loading security control plane');
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
    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('Reference: request-123'),
    );
  });
});
