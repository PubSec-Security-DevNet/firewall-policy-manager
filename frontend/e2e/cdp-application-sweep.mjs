import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';

const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:5173';
const endpoint = process.env.E2E_CDP_ENDPOINT ?? 'http://127.0.0.1:9222';
const screenshotDir =
  process.env.E2E_APPLICATION_SCREENSHOT_DIR ?? '/tmp/firewall-manager-cdp-application';
mkdirSync(screenshotDir, { recursive: true });

const nav = [
  ['Home', 'Security posture', 'home'],
  ['Policies', 'Policy browser', 'policies'],
  ['Rules', 'Rules workspace', 'rules'],
  ['Objects', 'Object inventory', 'objects'],
  ['Changes', 'ChangeSets', 'changes'],
  ['Users', 'Users', 'users'],
  ['Groups', 'Groups', 'groups'],
  ['Access grants', 'Access grants', 'grants'],
  ['Identity providers', 'Identity providers', 'identity-providers'],
  ['Provider connections', 'Provider connections', 'providers'],
  ['Sync & drift', 'Sync & drift', 'sync'],
  ['All ChangeSets', 'All ChangeSets', 'changesets-admin'],
  ['Deployments', 'Deployments', 'deployments'],
  ['Audit', 'Audit', 'audit'],
  ['Pending approvals', 'Pending approvals', 'approvals'],
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function monitor(page, events) {
  page.on('pageerror', (error) => events.push(`pageerror: ${error.message}`));
  page.on('requestfailed', (request) =>
    events.push(`requestfailed: ${request.method()} ${request.url()}`),
  );
  page.on('response', (response) => {
    if (response.status() >= 500) events.push(`http ${response.status()}: ${response.url()}`);
  });
  page.on('console', (message) => {
    if (['error', 'warning'].includes(message.type()))
      events.push(`console ${message.type()}: ${message.text()}`);
  });
}

async function clickNav(page, label) {
  const button = page.getByRole('button', { name: label, exact: true });
  await button.scrollIntoViewIfNeeded();
  await button.click();
}

async function screenshot(page, name) {
  const loading = page.locator('[role="status"]');
  if (await loading.count()) {
    await loading
      .first()
      .waitFor({ state: 'detached', timeout: 20_000 })
      .catch(() => {});
  }
  await page.waitForTimeout(350);
  await page.screenshot({ path: `${screenshotDir}/${name}.png`, fullPage: true });
}

async function closeOverlay(page) {
  const close = page.getByRole('button', { name: /^(Cancel|Close|Done|Back)$/i }).last();
  if (await close.count()) await close.click({ force: true });
  else await page.keyboard.press('Escape');
  await page.waitForTimeout(200);
}

async function inspectDialog(page, buttonName, name) {
  const button = page.getByRole('button', { name: buttonName, exact: true }).first();
  if (!(await button.count()) || !(await button.isVisible())) return false;
  await button.scrollIntoViewIfNeeded();
  await button.click({ force: true });
  await page.waitForTimeout(250);
  await screenshot(page, name);
  await closeOverlay(page);
  return true;
}

async function inspectFirst(page, buttonName, name) {
  const button = page.getByRole('button', { name: buttonName, exact: true }).first();
  if (!(await button.count()) || !(await button.isVisible())) return false;
  await button.scrollIntoViewIfNeeded();
  await button.click({ force: true });
  await page.waitForTimeout(250);
  await screenshot(page, name);
  await closeOverlay(page);
  return true;
}

async function selectFinanceDefaultPolicy(page) {
  // Return to a clean delegated-workspace mount after the admin route sweep; this
  // exercises the actual context-loading state rather than relying on a prior route.
  await page.setExtraHTTPHeaders({ 'X-Dev-User': 'viewer@example.test' });
  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Security posture' }).waitFor({ timeout: 20_000 });
  await clickNav(page, 'Policies');
  await page.getByRole('heading', { name: 'Policy browser' }).waitFor();
  const loading = page.locator('[role="status"]');
  if (await loading.count())
    await loading
      .first()
      .waitFor({ state: 'detached', timeout: 20_000 })
      .catch(() => {});
  await page.locator('tbody tr').first().waitFor({ timeout: 20_000 });
  const row = page.locator('tbody tr').filter({ hasText: 'FinanceDefault Access Control Policy' });
  assert((await row.count()) > 0, 'Finance Default Access Control Policy mapping missing');
  await row.getByRole('button', { name: 'Select', exact: true }).click({ force: true });
  await page
    .getByText('Default Access Control Policy', { exact: true })
    .first()
    .waitFor({ timeout: 20_000 });
}

async function run() {
  const browser = await chromium.connectOverCDP(endpoint);
  const context = browser.contexts()[0];
  assert(context, 'CDP browser has no usable context');
  const page = await context.newPage();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.setExtraHTTPHeaders({ 'X-Dev-User': 'admin@example.test' });
  const events = [];
  monitor(page, events);
  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Security posture' }).waitFor({ timeout: 20_000 });

  const screens = [];
  for (const [label, heading, file] of nav) {
    await clickNav(page, label);
    await page.getByRole('heading', { name: heading }).first().waitFor({ timeout: 20_000 });
    await screenshot(page, `screen-${file}`);
    screens.push(file);
  }

  await selectFinanceDefaultPolicy(page);
  await screenshot(page, 'delegated-policy-browser-finance-default');

  await clickNav(page, 'Rules');
  await page.getByRole('heading', { name: 'Rules workspace' }).waitFor();
  await screenshot(page, 'delegated-rules-loaded');
  await inspectDialog(page, /Create rule|New rule/i, 'delegated-rules-create-dialog');

  await clickNav(page, 'Objects');
  await page.getByRole('heading', { name: 'Object inventory' }).waitFor();
  await screenshot(page, 'delegated-objects-loaded');
  await inspectDialog(page, 'Create object', 'delegated-objects-create-dialog');
  await inspectFirst(page, 'Modify', 'delegated-objects-modify-dialog');
  await inspectFirst(page, 'View changes', 'delegated-objects-change-history');
  const deleteButton = page.getByRole('button', { name: 'Delete', exact: true }).first();
  if ((await deleteButton.count()) && (await deleteButton.isVisible())) {
    await deleteButton.click({ force: true });
    await screenshot(page, 'delegated-objects-delete-confirmation');
    await closeOverlay(page);
  }

  await clickNav(page, 'Changes');
  await page.getByRole('heading', { name: 'ChangeSets', exact: true }).waitFor();
  await screenshot(page, 'delegated-changes-loaded');
  await inspectFirst(page, 'View details', 'delegated-changes-details');

  await page.setExtraHTTPHeaders({ 'X-Dev-User': 'admin@example.test' });
  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Security posture' }).waitFor({ timeout: 20_000 });

  await clickNav(page, 'Users');
  await page.getByRole('heading', { name: 'Users' }).waitFor();
  await screenshot(page, 'admin-users-loaded');
  await inspectDialog(page, 'Create User', 'admin-users-create-dialog');
  await inspectFirst(page, 'Manage Groups', 'admin-users-membership-dialog');
  await inspectFirst(page, 'Manage role', 'admin-users-role-dialog');

  await clickNav(page, 'Groups');
  await page.getByRole('heading', { name: 'Groups' }).waitFor();
  await screenshot(page, 'admin-groups-loaded');
  await inspectDialog(page, 'Create Group', 'admin-groups-create-dialog');
  await inspectFirst(page, 'Manage members', 'admin-groups-members-dialog');

  await clickNav(page, 'Access grants');
  await page.getByRole('heading', { name: 'Access grants' }).waitFor();
  await screenshot(page, 'admin-grants-loaded');
  for (const [label, file] of [
    ['Add group delegation', 'group-policy-delegation'],
    ['Add User policy grant', 'user-policy-grant'],
    ['Add network object access', 'network-object-grant'],
    ['Add port object access', 'port-object-grant'],
    ['Add URL object access', 'url-object-grant'],
    ['Add security zone access', 'security-zone-grant'],
    ['Add authorized IP range', 'ip-range-grant'],
    ['Add object creation right', 'object-creation-grant'],
    ['Add category mapping', 'category-mapping'],
  ])
    await inspectDialog(page, label, `admin-grants-${file}-dialog`);
  await inspectFirst(page, 'Modify', 'admin-grants-modify-dialog');

  await clickNav(page, 'Identity providers');
  await page.getByRole('heading', { name: 'Identity providers' }).waitFor();
  await screenshot(page, 'admin-identity-providers-loaded');
  await inspectDialog(page, 'Add identity provider', 'admin-identity-provider-dialog');

  await clickNav(page, 'Provider connections');
  await page.getByRole('heading', { name: 'Provider connections' }).waitFor();
  await screenshot(page, 'admin-provider-connections-loaded');
  await inspectDialog(page, 'Add Connection', 'admin-provider-add-dialog');
  await inspectFirst(page, 'Edit connection', 'admin-provider-edit-dialog');

  await clickNav(page, 'Sync & drift');
  await page.getByRole('heading', { name: 'Sync & drift' }).waitFor();
  await screenshot(page, 'admin-sync-drift-loaded');
  await inspectFirst(page, 'Refresh from provider', 'admin-sync-refresh-state');

  await clickNav(page, 'All ChangeSets');
  await page.getByRole('heading', { name: 'All ChangeSets' }).waitFor();
  await screenshot(page, 'admin-all-changesets-loaded');
  await inspectFirst(page, 'View details', 'admin-all-changeset-details');

  await clickNav(page, 'Deployments');
  await page.getByRole('heading', { name: 'Deployments' }).waitFor();
  await screenshot(page, 'admin-deployments-loaded');
  await inspectFirst(page, 'View details', 'admin-deployment-details');

  await clickNav(page, 'Audit');
  await page.getByRole('heading', { name: 'Audit' }).waitFor();
  await screenshot(page, 'admin-audit-loaded');
  await inspectFirst(page, 'View details', 'admin-audit-details');

  await clickNav(page, 'Pending approvals');
  await page.getByRole('heading', { name: 'Pending approvals' }).waitFor();
  await screenshot(page, 'approvals-loaded-empty-or-pending');

  const metrics = await page.evaluate(() => ({
    width: innerWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  assert(
    metrics.scrollWidth <= metrics.width + 1,
    `final screen overflow: ${JSON.stringify(metrics)}`,
  );
  assert(events.length === 0, events.join('\n'));
  console.log(JSON.stringify({ screens, screenshots: screenshotDir, events, metrics }, null, 2));
  await page.close();
  await browser.close();
}

run().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : error);
  process.exitCode = 1;
});
