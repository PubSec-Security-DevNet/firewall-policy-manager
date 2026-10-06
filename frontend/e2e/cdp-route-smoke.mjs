import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';

const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:5173';
const endpoint = process.env.E2E_CDP_ENDPOINT ?? 'http://127.0.0.1:9222';
const screenshotDir = process.env.E2E_ROUTE_SCREENSHOT_DIR ?? '/tmp/firewall-manager-cdp-routes';
const navigation = [
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

function monitor(page) {
  const events = [];
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
  return events;
}

async function prepare(page, user) {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.setExtraHTTPHeaders({ 'X-Dev-User': user });
}

async function clickNav(page, label) {
  const button = page.getByRole('button', { name: label, exact: true });
  await button.scrollIntoViewIfNeeded();
  await button.click();
}

async function routeMetrics(page) {
  return page.evaluate(() => ({
    width: innerWidth,
    scrollWidth: document.documentElement.scrollWidth,
    height: document.documentElement.scrollHeight,
    headings: [...document.querySelectorAll('h1,h2,h3')]
      .map((node) => node.textContent?.trim())
      .filter(Boolean),
    rawUuidCount: (
      document.body.innerText.match(
        /[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi,
      ) ?? []
    ).length,
  }));
}

async function accessibility(page) {
  const source = readFileSync(
    new URL('../node_modules/axe-core/axe.min.js', import.meta.url),
    'utf8',
  );
  await page.addScriptTag({ content: source });
  return page.evaluate(async () => {
    const result = await window.axe.run(document, { runOnly: ['wcag2a', 'wcag2aa'] });
    return result.violations
      .filter((violation) => ['critical', 'serious'].includes(violation.impact))
      .map((violation) => ({
        id: violation.id,
        impact: violation.impact,
        nodes: violation.nodes.length,
      }));
  });
}

async function run() {
  const browser = await chromium.connectOverCDP(endpoint);
  const context = browser.contexts()[0];
  assert(context, 'CDP browser has no usable context');
  const page = await context.newPage();
  await prepare(page, 'admin@example.test');
  const events = monitor(page);
  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Security posture' }).waitFor({ timeout: 20_000 });

  const routeResults = [];
  for (const [label, expectedHeading, route] of navigation) {
    await clickNav(page, label);
    await page.getByRole('heading', { name: expectedHeading }).first().waitFor({ timeout: 20_000 });
    await page.waitForTimeout(400);
    const metrics = await routeMetrics(page);
    assert(
      metrics.scrollWidth <= metrics.width + 1,
      `${route} horizontal overflow: ${JSON.stringify(metrics)}`,
    );
    const active = await page
      .getByRole('button', { name: label, exact: true })
      .getAttribute('aria-current');
    assert(active === 'page', `${route} did not mark its navigation item active`);
    await page.screenshot({ path: `${screenshotDir}/${route}.png`, fullPage: true });
    routeResults.push({ route, ...metrics });
  }

  const keyA11y = [];
  for (const route of ['home', 'rules', 'objects', 'providers', 'deployments', 'audit']) {
    const item = routeResults.find((result) => result.route === route);
    const label = navigation.find(([, , value]) => value === route)?.[0];
    if (!item || !label) continue;
    await clickNav(page, label);
    keyA11y.push({ route, violations: await accessibility(page) });
  }

  await clickNav(page, 'Provider connections');
  await page.getByRole('heading', { name: 'Provider connections' }).waitFor();
  await page.getByRole('button', { name: 'Add Connection', exact: true }).click();
  await page.getByRole('dialog', { name: 'Add Provider Connection' }).waitFor();
  assert(
    await page.getByLabel('Display name').isVisible(),
    'provider connection form did not render',
  );
  await page.getByRole('button', { name: 'Close', exact: true }).click();

  await clickNav(page, 'Deployments');
  await page.getByRole('heading', { name: 'Deployments' }).waitFor();
  const details = page.getByRole('button', { name: 'View details', exact: true }).first();
  if (await details.count()) {
    await details.click();
    await page.getByRole('dialog', { name: 'Deployment details' }).waitFor();
    await page.getByRole('button', { name: 'Close deployment details', exact: true }).click();
  }

  const delegated = await context.newPage();
  await prepare(delegated, 'viewer@example.test');
  const delegatedEvents = monitor(delegated);
  await delegated.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await delegated.getByRole('heading', { name: 'Security posture' }).waitFor({ timeout: 20_000 });
  await clickNav(delegated, 'Policies');
  await delegated.getByRole('heading', { name: 'Policy browser' }).waitFor();
  const mappingRows = delegated.locator('tbody tr');
  await mappingRows.first().waitFor({ timeout: 20_000 });
  assert((await mappingRows.filter({ hasText: 'Finance' }).count()) > 0, 'Finance mapping missing');
  await mappingRows
    .filter({ hasText: 'Finance' })
    .last()
    .getByRole('button', { name: 'Select', exact: true })
    .click({ force: true });
  await delegated.locator('.fm-working-context-value').filter({ hasText: 'Finance' }).waitFor();
  await clickNav(delegated, 'Objects');
  await delegated.getByRole('heading', { name: 'Object inventory' }).waitFor();
  const objectModify = delegated.getByRole('button', { name: /Modify/ }).first();
  if (await objectModify.count()) {
    await objectModify.click();
    await delegated.getByRole('heading', { name: 'Modify firewall object' }).waitFor();
    await delegated.getByRole('button', { name: 'Cancel', exact: true }).click();
  }
  await clickNav(delegated, 'Rules');
  await delegated.getByRole('heading', { name: 'Rules workspace' }).waitFor();
  const createRule = delegated.getByRole('button', { name: /Create rule|New rule/i }).first();
  if (await createRule.count()) {
    await createRule.click();
    await delegated.getByRole('dialog').first().waitFor();
    await delegated
      .getByRole('button', { name: /Cancel|Close/ })
      .last()
      .click();
  }

  const mobile = await context.newPage();
  await prepare(mobile, 'admin@example.test');
  await mobile.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await mobile.getByRole('heading', { name: 'Security posture' }).waitFor();
  for (const [label, expectedHeading] of navigation.slice(0, 5)) {
    await mobile.setViewportSize({ width: 1440, height: 900 });
    await clickNav(mobile, label);
    await mobile.getByRole('heading', { name: expectedHeading }).first().waitFor();
    await mobile.setViewportSize({ width: 390, height: 844 });
    const dimensions = await mobile.evaluate(() => ({
      width: innerWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    assert(
      dimensions.scrollWidth <= dimensions.width + 1,
      `mobile ${label} overflow: ${JSON.stringify(dimensions)}`,
    );
  }

  const allEvents = [...events, ...delegatedEvents];
  assert(allEvents.length === 0, allEvents.join('\n'));
  const a11yFailures = keyA11y.flatMap((result) =>
    result.violations.map((violation) => ({ ...violation, route: result.route })),
  );
  assert(a11yFailures.length === 0, `accessibility violations: ${JSON.stringify(a11yFailures)}`);
  console.log(JSON.stringify({ routes: routeResults, a11y: keyA11y, events: allEvents }, null, 2));
  await mobile.close();
  await delegated.close();
  await page.close();
  await browser.close();
}

run().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : error);
  process.exitCode = 1;
});
