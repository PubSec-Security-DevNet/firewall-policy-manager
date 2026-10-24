// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { expect, test, type Page } from '@playwright/test';

// All API requests are intercepted; these journeys require only the frontend server.
async function openAuthenticatedApplication(page: Page) {
  const requests: string[] = [];
  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const path = new URL(route.request().url()).pathname;
      requests.push(path);
      const responses: Record<string, unknown> = {
        '/api/v1/session': {
          environment: 'test',
          authentication_mode: 'oidc',
          user_id: 'session-user',
          email: 'admin@example.test',
          role: 'admin',
          groups: [],
        },
        '/api/v1/overview': {
          organization: 'Example Organization',
          counts: { managers: 0, policies: 0, rules: 0, objects: 0, change_sets: 0 },
          providers: [],
        },
        '/api/v1/approvals/pending': { count: 0, items: [] },
        '/api/v1/admin/provider-connections': { items: [], total: 0 },
        '/api/v1/dev/users': [],
        '/api/v1/auth/providers': [
          { provider_id: 'enterprise', kind: 'generic', display_name: 'Enterprise SSO' },
        ],
        '/api/v1/auth/contact': { email: null },
        '/api/v1/auth/setup/status': { available: false, recovery: false },
        '/api/v1/admin/smtp': {
          host: 'smtp.example.test',
          port: 587,
          from_address: 'firewall@example.test',
          encryption: 'STARTTLS',
          authentication_required: false,
          username: null,
          password_configured: false,
          custom_ca_configured: false,
          revision: 1,
        },
      };
      if (!(path in responses)) throw new Error(`Unexpected API request: ${path}`);
      await route.fulfill({ json: responses[path] });
    },
  );
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Security posture' })).toBeVisible();
  await page.evaluate(() => {
    sessionStorage.setItem('firewall-manager.active-context.session-user', 'private context');
  });
  return requests;
}

async function expectSignIn(page: Page) {
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  await expect(
    page.getByText('Your session has expired. Sign in again to continue.'),
  ).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: /Enterprise SSO/ })).toHaveAttribute(
    'href',
    '/api/v1/auth/enterprise/login',
  );
  expect(
    await page.evaluate(() =>
      sessionStorage.getItem('firewall-manager.active-context.session-user'),
    ),
  ).toBeNull();
}

for (const failure of [
  { status: 401, body: 'Unauthorized', contentType: 'text/plain' },
  {
    status: 403,
    json: {
      error: { code: 'NOT_AUTHENTICATED', message: 'Session expired.', correlation_id: 'expired' },
    },
  },
]) {
  test(`returns to sign-in when navigation receives ${failure.status}`, async ({ page }) => {
    const requests = await openAuthenticatedApplication(page);
    const initialSessionRequests = requests.filter((path) => path === '/api/v1/session').length;
    await page.route('**/api/v1/deployments', (route) => route.fulfill(failure));
    await page.getByRole('button', { name: 'Deployments', exact: true }).click();
    await expectSignIn(page);
    // An explicit sign-in is required; no reload or automatic OIDC redirect loop.
    expect(requests.filter((path) => path === '/api/v1/session')).toHaveLength(
      initialSessionRequests,
    );
  });
}

test('discards an expired session after a mutation without replaying the action', async ({
  page,
}) => {
  await openAuthenticatedApplication(page);
  await page.getByRole('button', { name: 'SMTP notifications', exact: true }).click();
  await expect(page.getByLabel('SMTP host')).toHaveValue('smtp.example.test');
  await page.getByLabel('SMTP host').fill('unsaved.example.test');
  let mutations = 0;
  await page.route('**/api/v1/admin/smtp', async (route) => {
    expect(route.request().method()).toBe('PUT');
    mutations++;
    await route.fulfill({ status: 401, body: '' });
  });
  await page.getByRole('button', { name: 'Save SMTP settings' }).click();
  await expectSignIn(page);
  await expect(page.getByLabel('SMTP host')).toHaveCount(0);
  expect(mutations).toBe(1);
});

test('returns to sign-in on background expiry and stops authenticated polling', async ({
  page,
}) => {
  await page.clock.install();
  await openAuthenticatedApplication(page);
  let expiredRequests = 0;
  await page.route('**/api/v1/approvals/pending', async (route) => {
    expiredRequests++;
    await route.fulfill({ status: 401, body: '' });
  });
  await page.clock.fastForward(16_000);
  await expectSignIn(page);
  expect(expiredRequests).toBe(1);
  await page.clock.fastForward(45_000);
  expect(expiredRequests).toBe(1);
});

for (const status of [403, 409, 500]) {
  test(`keeps the editor and draft for unrelated HTTP ${status} failures`, async ({ page }) => {
    await openAuthenticatedApplication(page);
    await page.getByRole('button', { name: 'SMTP notifications', exact: true }).click();
    await expect(page.getByLabel('SMTP host')).toHaveValue('smtp.example.test');
    await page.getByLabel('SMTP host').fill('unsaved.example.test');
    await page.route('**/api/v1/admin/smtp', (route) =>
      route.fulfill({
        status,
        json: {
          error: {
            code: 'SAVE_FAILED',
            message: 'Settings could not be saved.',
            correlation_id: 'ref',
          },
        },
      }),
    );
    await page.getByRole('button', { name: 'Save SMTP settings' }).click();
    await expect(page.getByRole('alert')).toContainText('Settings could not be saved.');
    await expect(page.getByLabel('SMTP host')).toHaveValue('unsaved.example.test');
    await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Welcome back.' })).toHaveCount(0);
  });
}
