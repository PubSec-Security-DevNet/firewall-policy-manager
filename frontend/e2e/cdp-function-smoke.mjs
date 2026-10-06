import { chromium } from 'playwright';

const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:5173';
const endpoint = process.env.E2E_CDP_ENDPOINT ?? 'http://127.0.0.1:9222';

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

async function waitSettled(page) {
  const status = page.locator('[role="status"]');
  if (await status.count())
    await status
      .first()
      .waitFor({ state: 'detached', timeout: 20_000 })
      .catch(() => {});
  await page.waitForTimeout(250);
}

async function nav(page, label, heading) {
  console.log(`NAV ${label}`);
  const button = page.getByRole('button', { name: label, exact: true });
  await button.scrollIntoViewIfNeeded();
  await button.click();
  await page
    .getByRole('heading', { name: heading, exact: true })
    .first()
    .waitFor({ timeout: 20_000 });
  await waitSettled(page);
}

async function closeOverlay(page) {
  const close = page.getByRole('button', { name: /^(Cancel|Close|Done|Back)$/i }).last();
  if (await close.count()) await close.click({ force: true });
  else await page.keyboard.press('Escape');
  await page.waitForTimeout(150);
}

async function openAndClose(page, label, name) {
  console.log(`OPEN ${label}`);
  const button = page.getByRole('button', { name: label, exact: true }).first();
  if (!(await button.count()) || !(await button.isVisible())) return false;
  await button.scrollIntoViewIfNeeded();
  await button.click({ force: true });
  await page.waitForTimeout(250);
  if (name && !(await page.getByText(name, { exact: true }).count())) {
    throw new Error(`${label} did not open ${name}`);
  }
  await closeOverlay(page);
  return true;
}

async function dismissConfirmation(page, label) {
  console.log(`CONFIRM ${label}`);
  const button = page.getByRole('button', { name: label, exact: true }).first();
  if (!(await button.count()) || !(await button.isVisible())) return false;
  await button.scrollIntoViewIfNeeded();
  await button.click({ force: true });
  await page.waitForTimeout(200);
  return true;
}

async function run() {
  const browser = await chromium.connectOverCDP(endpoint);
  const context = browser.contexts()[0];
  const page = await context.newPage();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.setExtraHTTPHeaders({ 'X-Dev-User': 'admin@example.test' });
  const events = [];
  page.on('pageerror', (error) => events.push(`pageerror: ${error.message}`));
  page.on('requestfailed', (request) => events.push(`requestfailed: ${request.url()}`));
  page.on('response', (response) => {
    if (response.status() >= 500) events.push(`http ${response.status()}: ${response.url()}`);
  });
  page.on('console', (message) => {
    if (['error', 'warning'].includes(message.type()))
      events.push(`console ${message.type()}: ${message.text()}`);
  });
  page.on('dialog', async (dialog) => {
    try {
      await dialog.dismiss();
    } catch {
      // The application may close a confirmation while Playwright is attaching to it.
    }
  });
  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Security posture' }).waitFor({ timeout: 20_000 });

  const tested = [];
  await nav(page, 'Users', 'Users');
  tested.push(['users-create', await openAndClose(page, 'Create User', 'Create User')]);
  tested.push(['users-membership', await openAndClose(page, 'Manage Groups', 'Manage Groups')]);
  tested.push(['users-role', await openAndClose(page, 'Change role', 'Change role')]);
  tested.push(['users-disable-confirmation', await dismissConfirmation(page, 'Disable')]);

  await nav(page, 'Groups', 'Groups');
  tested.push(['groups-create', await openAndClose(page, 'Create Group', 'Create Group')]);
  tested.push(['groups-membership', await openAndClose(page, 'Manage members', 'Manage members')]);
  tested.push(['groups-disable-confirmation', await dismissConfirmation(page, 'Disable')]);
  const executionToggle = page
    .getByRole('button', { name: /^(Allow direct execution|Approval required)$/, exact: true })
    .first();
  if ((await executionToggle.count()) && (await executionToggle.isVisible())) {
    const initialLabel = await executionToggle.innerText();
    await executionToggle.click({ force: true });
    await page.waitForTimeout(500);
    const restoredLabel =
      initialLabel === 'Approval required' ? 'Allow direct execution' : 'Approval required';
    const restoreToggle = page.getByRole('button', { name: restoredLabel, exact: true }).first();
    if (await restoreToggle.count()) {
      await restoreToggle.click({ force: true });
      await page.waitForTimeout(500);
    }
    tested.push(['groups-direct-execution-toggle', true]);
  } else tested.push(['groups-direct-execution-toggle', false]);

  await nav(page, 'Access grants', 'Access grants');
  for (const [label, title] of [
    ['Add group delegation', 'Add group policy delegation'],
    ['Add User policy grant', 'Add User policy grant'],
  ]) {
    tested.push([label, await openAndClose(page, label, title)]);
  }
  tested.push(['grant-modify-or-details', await openAndClose(page, 'Modify')]);
  tested.push(['grant-revoke-confirmation', await dismissConfirmation(page, 'Revoke')]);
  const resourceTab = page.getByRole('tab', { name: 'Resource access', exact: true });
  if (await resourceTab.count()) {
    await resourceTab.click();
    await waitSettled(page);
    for (const [tab, label] of [
      ['Networks', 'Add network object access'],
      ['Ports', 'Add port object access'],
      ['URLs', 'Add URL object access'],
      ['Applications', 'Add application object access'],
      ['Zones', 'Add security zone access'],
      ['IP ranges', 'Add authorized IP range'],
      ['Creation', 'Add object creation right'],
    ]) {
      await page.getByRole('tab', { name: tab, exact: true }).click();
      await waitSettled(page);
      tested.push([label, await openAndClose(page, label, label)]);
    }
  }
  const categoryTab = page.getByRole('tab', { name: 'Category mappings', exact: true });
  if (await categoryTab.count()) {
    await categoryTab.click();
    tested.push([
      'Add category mapping',
      await openAndClose(page, 'Add category mapping', 'Add category mapping'),
    ]);
  }

  await nav(page, 'Identity providers', 'Identity providers');
  assert(
    await page.getByRole('heading', { name: 'Add identity provider', exact: true }).count(),
    'OIDC add form missing',
  );
  tested.push(['identity-provider-form', true]);

  await nav(page, 'Provider connections', 'Provider connections');
  tested.push([
    'provider-add',
    await openAndClose(page, 'Add Connection', 'Add Provider Connection'),
  ]);
  const editProviders = page.getByRole('button', { name: 'Edit connection', exact: true });
  let providerEditOpened = false;
  for (let index = 0; index < (await editProviders.count()); index += 1) {
    const editProvider = editProviders.nth(index);
    if (!(await editProvider.isVisible())) continue;
    await editProvider.click({ force: true });
    await page.waitForTimeout(500);
    if (
      await page
        .locator('.fm-provider-settings')
        .first()
        .isVisible()
        .catch(() => false)
    ) {
      providerEditOpened = true;
      break;
    }
  }
  tested.push(['provider-edit', providerEditOpened]);
  if (providerEditOpened) {
    await page
      .getByRole('button', { name: 'Close settings', exact: true })
      .first()
      .click({ force: true });
  }
  tested.push([
    'provider-test-confirmation-or-result',
    await dismissConfirmation(page, 'Test connection'),
  ]);

  await nav(page, 'All ChangeSets', 'All ChangeSets');
  tested.push(['changeset-details', await openAndClose(page, 'View details', 'ChangeSet details')]);

  await nav(page, 'Deployments', 'Deployments');
  tested.push([
    'deployment-details',
    await openAndClose(page, 'View details', 'Deployment details'),
  ]);

  await nav(page, 'Audit', 'Audit');
  tested.push(['audit-details', await openAndClose(page, 'View details')]);

  await nav(page, 'Sync & drift', 'Sync & drift');
  tested.push(['sync-refresh', await dismissConfirmation(page, 'Refresh from provider')]);

  assert(
    tested.some(([, value]) => value),
    'No function paths were exercised',
  );
  assert(events.length === 0, events.join('\n'));
  console.log(JSON.stringify({ tested, events }, null, 2));
  await page.close();
  await browser.close();
}

run().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : error);
  process.exitCode = 1;
});
