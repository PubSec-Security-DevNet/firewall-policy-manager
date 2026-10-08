// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(resolve(here, 'docs-screenshots.json'), 'utf8'));
const baseURL = process.env.DOCS_SCREENSHOT_BASE_URL ?? 'http://localhost:5173';
const endpoint = process.env.DOCS_SCREENSHOT_CDP_ENDPOINT ?? 'http://127.0.0.1:9222';
const outputDir = resolve(
  here,
  process.env.DOCS_SCREENSHOT_OUTPUT ?? '../../docs-site/public/screenshots',
);
const captureUser = process.env.DOCS_SCREENSHOT_USER ?? 'admin@example.test';

mkdirSync(outputDir, { recursive: true });

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function settle(page, entry) {
  await page
    .getByRole('heading', { name: entry.heading, exact: true })
    .first()
    .waitFor({ timeout: 20_000 });
  if (entry.waitSelector)
    await page.locator(entry.waitSelector).first().waitFor({ timeout: 20_000 });
  const loading = page.locator('[role="status"]');
  if (await loading.count())
    await loading
      .first()
      .waitFor({ state: 'detached', timeout: 20_000 })
      .catch(() => {});
  await page.waitForTimeout(450);
}

async function run() {
  const browser = await chromium.connectOverCDP(endpoint);
  const context = browser.contexts()[0];
  assert(context, 'The CDP browser has no usable context. Start an isolated Chrome profile first.');
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('requestfailed', (request) =>
    errors.push(`requestfailed: ${request.method()} ${request.url()}`),
  );
  page.on('response', (response) => {
    if (response.status() >= 500) errors.push(`http ${response.status()}: ${response.url()}`);
  });
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(`console error: ${message.text()}`);
  });

  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.setExtraHTTPHeaders({ 'X-Dev-User': captureUser });
  await page.goto(baseURL, { waitUntil: 'domcontentloaded' });
  await page.addStyleTag({
    content:
      '.fm-dev-mode-badge,.fm-session-identity,.fm-development-user-selector{display:none!important}',
  });

  for (const entry of manifest) {
    const button = page.getByRole('button', { name: entry.nav, exact: true });
    await button.scrollIntoViewIfNeeded();
    await button.click();
    await settle(page, entry);
    const pageText = await page.locator('body').innerText();
    const unsafeEmails = [...pageText.matchAll(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g)]
      .map((match) => match[0])
      .filter((email) => !email.endsWith('@example.test'));
    assert(
      unsafeEmails.length === 0,
      `${entry.route} exposes non-fixture email addresses: ${unsafeEmails.join(', ')}`,
    );
    const dimensions = await page.evaluate(() => ({
      width: innerWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    assert(
      dimensions.scrollWidth <= dimensions.width + 1,
      `${entry.route} has horizontal overflow`,
    );
    await page.screenshot({
      path: resolve(outputDir, entry.output),
      clip: { x: 0, y: 0, width: 1440, height: entry.clipHeight },
    });
  }

  assert(errors.length === 0, errors.join('\n'));
  await page.close();
  await browser.close();
  process.stdout.write(`Captured ${manifest.length} documentation screenshots in ${outputDir}\n`);
}

run().catch((error) => {
  process.stderr.write(`${error instanceof Error ? (error.stack ?? error.message) : error}\n`);
  process.exitCode = 1;
});
