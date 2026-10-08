// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';

const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:5173';
const endpoint = process.env.E2E_CDP_ENDPOINT ?? 'http://127.0.0.1:9222';
const screenshotDir = process.env.E2E_FAULT_SCREENSHOT_DIR ?? '/tmp/firewall-manager-cdp-faults';
mkdirSync(screenshotDir, { recursive: true });

const unauthenticated = {
  status: 401,
  contentType: 'application/json',
  body: JSON.stringify({
    error: {
      code: 'NOT_AUTHENTICATED',
      message: 'Authentication required',
      correlation_id: 'e2e-unauthenticated',
    },
  }),
};

async function runCase(browser, name, setup, assertion) {
  const page = await browser.contexts()[0].newPage();
  const events = [];
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.route('**/api/v1/session', (route) => route.fulfill(unauthenticated));
  if (setup) await setup(page);
  page.on('pageerror', (error) => events.push(`pageerror: ${error.message}`));
  page.on('requestfailed', (request) => events.push(`requestfailed: ${request.url()}`));
  page.on('console', (message) => {
    if (
      ['error', 'warning'].includes(message.type()) &&
      !/status of (401|503)/i.test(message.text())
    ) {
      events.push(`console: ${message.text()}`);
    }
  });
  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await assertion(page);
  await page.screenshot({ path: `${screenshotDir}/${name}.png`, fullPage: true });
  await page.close();
  if (events.length) throw new Error(`${name}: ${events.join('\n')}`);
  return { name, screenshot: `${name}.png`, events };
}

async function run() {
  const browser = await chromium.connectOverCDP(endpoint);
  const results = [];
  results.push(
    await runCase(browser, 'login-unauthenticated', null, async (page) => {
      await page.getByRole('heading', { name: 'Welcome back.' }).waitFor({ timeout: 20_000 });
    }),
  );
  results.push(
    await runCase(
      browser,
      'login-no-provider',
      async (page) => {
        await page.route('**/api/v1/auth/providers', (route) =>
          route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
        );
      },
      async (page) => {
        await page.getByRole('heading', { name: 'Welcome back.' }).waitFor({ timeout: 20_000 });
        await page.getByText('No identity provider configured', { exact: true }).waitFor();
      },
    ),
  );
  results.push(
    await runCase(
      browser,
      'application-api-error',
      async (page) => {
        await page.unroute('**/api/v1/session');
        await page.route('**/api/v1/session', (route) =>
          route.fulfill({
            status: 503,
            contentType: 'application/json',
            body: JSON.stringify({
              error: {
                code: 'SERVICE_UNAVAILABLE',
                message: 'Control plane unavailable',
                correlation_id: 'e2e-fault',
              },
            }),
          }),
        );
      },
      async (page) => {
        await page.getByText('Unable to load this view').waitFor({ timeout: 20_000 });
        await page.getByText('Control plane unavailable').waitFor();
      },
    ),
  );
  await browser.close();
  console.log(JSON.stringify({ screenshots: screenshotDir, results }, null, 2));
}

run().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : error);
  process.exitCode = 1;
});
