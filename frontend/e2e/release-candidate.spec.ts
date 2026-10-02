import { expect, test, type Page } from '@playwright/test';

function collectRuntimeFailures(page: Page) {
  const failures: string[] = [];
  page.on('pageerror', (error) => failures.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    const text = message.text();
    if (
      message.type() === 'error' &&
      text !== 'Failed to load resource: the server responded with a status of 404 (Not Found)'
    ) {
      failures.push(`console: ${text}`);
    }
  });
  page.on('requestfailed', (request) => {
    failures.push(
      `request: ${request.method()} ${request.url()} ${request.failure()?.errorText ?? ''}`,
    );
  });
  page.on('response', (response) => {
    if (response.status() >= 500) failures.push(`http ${response.status()}: ${response.url()}`);
  });
  return failures;
}

async function preparePage(page: Page, user = 'viewer@example.test') {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.setExtraHTTPHeaders({ 'X-Dev-User': user });
}

test.describe('release-candidate application journeys', () => {
  test('loads the delegated shell, switches Group context, and survives refresh', async ({
    page,
  }) => {
    await preparePage(page);
    const failures = collectRuntimeFailures(page);
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Security posture' })).toBeVisible();

    for (const label of ['Policies', 'Rules', 'Objects', 'Changes']) {
      await expect(page.getByRole('button', { name: label, exact: true })).toBeVisible();
    }

    await page.getByRole('button', { name: 'Policies', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Policy browser' })).toBeVisible();
    const financeRow = page.getByRole('row', { name: /Finance/ }).last();
    await financeRow.getByRole('button', { name: 'Select', exact: true }).click();
    await expect(page.locator('.fm-working-context-value')).toHaveText('Finance');

    await page.getByRole('button', { name: 'Objects', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Object inventory' })).toBeVisible();
    await expect(page.getByText('FINANCE__APP-SUBNET')).toBeVisible();

    await page.getByRole('button', { name: 'Policies', exact: true }).click();
    const engineeringRow = page.getByRole('row', { name: /Engineering/ }).last();
    await engineeringRow.getByRole('button', { name: 'Select', exact: true }).click();
    await expect(page.locator('.fm-working-context-value')).toHaveText('Engineering');
    await page.getByRole('button', { name: 'Objects', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Object inventory' })).toBeVisible();
    await expect(page.getByText('ENGINEERING__BUILD-SERVERS')).toBeVisible();
    await expect(page.getByText('FINANCE__APP-SUBNET')).toHaveCount(0);

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Object inventory' })).toHaveCount(0);
    await expect(page.locator('.fm-working-context-value')).toHaveText('Engineering');
    expect(failures, failures.join('\n')).toEqual([]);
  });

  test('loads administrative routes without server or browser errors', async ({ page }) => {
    await preparePage(page, 'admin@example.test');
    const failures = collectRuntimeFailures(page);
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Security posture' })).toBeVisible();

    for (const [nav, heading] of [
      ['Users', 'Users'],
      ['Groups', 'Groups'],
      ['Access grants', 'Access grants'],
      ['Provider connections', 'Provider connections'],
      ['Sync & drift', 'Sync & drift'],
      ['All ChangeSets', 'All ChangeSets'],
      ['Deployments', 'Deployments'],
      ['Audit', 'Audit'],
    ] as const) {
      await page.getByRole('button', { name: nav, exact: true }).click();
      await expect(page.getByRole('heading', { name: heading })).toBeVisible();
    }

    expect(failures, failures.join('\n')).toEqual([]);
  });

  test('denies a disabled development identity without exposing the application shell', async ({
    page,
  }) => {
    await preparePage(page, 'disabled@example.test');
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toHaveCount(0);
  });
});
