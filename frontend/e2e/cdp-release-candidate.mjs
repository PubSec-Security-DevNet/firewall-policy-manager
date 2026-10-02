import { chromium } from 'playwright';

const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:5173';
const endpoint = process.env.E2E_CDP_ENDPOINT ?? 'http://127.0.0.1:9222';
const navigation = [
  ['Home', 'Security posture'],
  ['Policies', 'Policy browser'],
  ['Rules', 'Rules workspace'],
  ['Objects', 'Object inventory'],
  ['Changes', 'ChangeSets'],
  ['Users', 'Users'],
  ['Groups', 'Groups'],
  ['Access grants', 'Access grants'],
  ['Identity providers', 'Identity providers'],
  ['Provider connections', 'Provider connections'],
  ['Sync & drift', 'Sync & drift'],
  ['All ChangeSets', 'All ChangeSets'],
  ['Deployments', 'Deployments'],
  ['Audit', 'Audit'],
  ['Pending approvals', 'Pending approvals'],
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function runtimeFailures(page) {
  const failures = [];
  page.on('pageerror', (error) => failures.push(`pageerror: ${error.message}`));
  page.on('requestfailed', (request) =>
    failures.push(`request: ${request.method()} ${request.url()}`),
  );
  page.on(
    'response',
    (response) =>
      response.status() >= 500 && failures.push(`http ${response.status()}: ${response.url()}`),
  );
  page.on('console', (message) => {
    if (message.type() === 'error' && !message.text().includes('status of 404')) {
      failures.push(`console: ${message.text()}`);
    }
  });
  return failures;
}

async function prepare(page, user) {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.setExtraHTTPHeaders({ 'X-Dev-User': user });
}

async function heading(page, name) {
  await page.getByRole('heading', { name }).waitFor({ timeout: 15_000 });
}

async function run() {
  const browser = await chromium.connectOverCDP(endpoint);
  const context = browser.contexts()[0];
  assert(context, 'CDP browser has no usable context');

  const page = await context.newPage();
  await prepare(page, 'admin@example.test');
  const failures = runtimeFailures(page);
  await page.goto(`${baseURL}/`);
  await heading(page, 'Security posture');
  for (const [label, expectedHeading] of navigation) {
    await page.getByRole('button', { name: label, exact: true }).click();
    await heading(page, expectedHeading);
  }
  assert(failures.length === 0, failures.join('\n'));
  console.log(`PASS all ${navigation.length} primary screens`);
  await page.close();

  const delegated = await context.newPage();
  await prepare(delegated, 'viewer@example.test');
  const delegatedFailures = runtimeFailures(delegated);
  await delegated.goto(`${baseURL}/`);
  await heading(delegated, 'Security posture');
  await delegated.getByRole('button', { name: 'Policies', exact: true }).click();
  await heading(delegated, 'Policy browser');
  await delegated
    .getByRole('row', { name: /Finance/ })
    .last()
    .getByRole('button', { name: 'Select', exact: true })
    .click();
  await delegated.locator('.fm-working-context-value').filter({ hasText: 'Finance' }).waitFor();
  await delegated.getByRole('button', { name: 'Objects', exact: true }).click();
  await delegated.getByText('FINANCE__APP-SUBNET').waitFor();
  await delegated.getByRole('button', { name: 'Policies', exact: true }).click();
  await delegated
    .getByRole('row', { name: /Engineering/ })
    .last()
    .getByRole('button', { name: 'Select', exact: true })
    .click();
  await delegated.locator('.fm-working-context-value').filter({ hasText: 'Engineering' }).waitFor();
  await delegated.getByRole('button', { name: 'Objects', exact: true }).click();
  await delegated.getByText('ENGINEERING__BUILD-SERVERS').waitFor();
  assert(
    (await delegated.getByText('FINANCE__APP-SUBNET').count()) === 0,
    'Finance object leaked into Engineering context',
  );
  assert(delegatedFailures.length === 0, delegatedFailures.join('\n'));
  console.log('PASS delegated context and object isolation');

  await delegated.getByRole('button', { name: 'Home', exact: true }).click();
  await heading(delegated, 'Security posture');
  await delegated.setViewportSize({ width: 390, height: 844 });
  const dimensions = await delegated.evaluate(() => ({
    width: innerWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  assert(
    dimensions.scrollWidth <= dimensions.width + 1,
    `horizontal overflow: ${JSON.stringify(dimensions)}`,
  );
  await delegated.locator('body').press('Tab');
  assert(
    await delegated.evaluate(() => document.activeElement?.tagName !== 'BODY'),
    'keyboard focus did not move',
  );
  console.log('PASS mobile viewport and keyboard focus');

  const disabled = await context.newPage();
  await prepare(disabled, 'disabled@example.test');
  await disabled.goto(`${baseURL}/`);
  await heading(disabled, 'Welcome back.');
  assert(
    (await disabled.getByRole('navigation', { name: 'Primary navigation' }).count()) === 0,
    'disabled user saw primary navigation',
  );
  console.log('PASS disabled-user denial');
  await disabled.close();
  await delegated.close();
  await browser.close();
}

run().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : error);
  process.exitCode = 1;
});
