// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { expect, test } from '@playwright/test';
type ReviewContext = { capabilities: string[]; objects: { name: string }[] };

test('an upgraded assignment requires individual administrator confirmation', async ({ page }) => {
  test.skip(
    process.env.LEGACY_UPGRADE_E2E !== '1',
    'Requires the isolated pre-0045 seeded upgrade fixture',
  );
  const admin = { 'X-Dev-User': 'admin@example.test' };
  const delegated = { 'X-Dev-User': 'viewer@example.test' };
  const response = await page.request.get('/api/v1/admin/legacy-ownership', { headers: admin });
  expect(response.ok()).toBeTruthy();
  const reviews = (await response.json()) as {
    id: string;
    resource_id: string;
    resource_type: string;
    group_id: string;
    policy_id: string;
    name: string;
  }[];
  const object = reviews.find(
    (r) => r.resource_type === 'OBJECT' && r.name === 'FINANCE__APP-SUBNET',
  );
  expect(object).toBeDefined();
  const scope = reviews.filter(
    (r) => r.group_id === object!.group_id && r.policy_id === object!.policy_id,
  );
  const contextUrl = `/api/v1/delegated/context?active_group_id=${object!.group_id}&policy_id=${object!.policy_id}`;
  const before = (await (
    await page.request.get(contextUrl, { headers: delegated })
  ).json()) as ReviewContext;
  expect(before.capabilities).toEqual(['view']);
  expect(before.objects).toEqual([]);
  expect(
    (await page.request.get('/api/v1/admin/legacy-ownership', { headers: delegated })).status(),
  ).toBe(403);
  await page.setExtraHTTPHeaders(delegated);
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Access grants', exact: true })).toHaveCount(0);
  await page.setExtraHTTPHeaders(admin);
  await page.reload();
  const failures: string[] = [];
  page.on('pageerror', (e) => failures.push(e.message));
  page.on('response', (r) => {
    if (r.status() >= 500) failures.push(`${r.status()} ${r.url()}`);
  });
  await page.getByRole('button', { name: 'Access grants', exact: true }).click();
  await expect(page.getByText('Legacy ownership review', { exact: true })).toBeVisible();
  for (const item of scope) {
    const card = page
      .locator('.fm-card')
      .filter({ hasText: `Resource ${item.resource_id}` })
      .last();
    await expect(card.getByText(/Review required/)).toBeVisible();
    await card.getByRole('button', { name: 'Review assignment' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('button', { name: 'Confirm this assignment' })).toBeDisabled();
    await dialog
      .getByLabel('Review evidence and reason')
      .fill(`Isolated upgrade fixture: reviewed resource ${item.resource_id}`);
    const confirmed = page.waitForResponse((r) =>
      r.url().endsWith(`/admin/legacy-ownership/${item.id}/confirm`),
    );
    await dialog.getByRole('button', { name: 'Confirm this assignment' }).click();
    expect((await confirmed).status()).toBe(200);
    await expect(dialog).not.toBeVisible();
  }
  const after = (await (
    await page.request.get(contextUrl, { headers: delegated })
  ).json()) as ReviewContext;
  expect(after.capabilities).toContain('modify_object');
  expect(
    after.objects.some((o: { name: string }) => o.name === 'FINANCE__APP-SUBNET'),
  ).toBeTruthy();
  await page.getByRole('button', { name: 'Audit', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Audit' })).toBeVisible();
  const auditRow = page.getByRole('row').filter({ hasText: 'Legacy Ownership Review' }).first();
  await auditRow.getByRole('button', { name: 'View details' }).click();
  await expect(page.getByRole('dialog')).toContainText('Explicit Legacy Authority Confirmation');
  expect(failures).toEqual([]);
});
