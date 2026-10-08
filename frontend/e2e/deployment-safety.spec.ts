// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { expect, test } from '@playwright/test';

// Controlled deployment API evidence; authentication/navigation use the isolated dev backend.
// Provider dispatch and takeover are tested separately through actual PostgreSQL workers.
test('shows completed, refused and uncertain deployment outcomes without unsafe retry', async ({
  page,
}) => {
  await page.setExtraHTTPHeaders({ 'X-Dev-User': 'admin@example.test' });
  const now = new Date().toISOString();
  const base = {
    organization_id: 'org',
    provider_transaction_id: 'transaction',
    provider_connection_id: null,
    rollback_state: null,
    rollback_external_operation_id: null,
    rollback_requested_by_user_id: null,
    rollback_device_results: [],
    rollback_failure_info: {},
    rollback_eligible: false,
    rollback_unavailable_reason: null,
    requested_by_user_id: null,
    approved_by_user_id: null,
    target_device_ids: ['device'],
    device_names: { device: 'Controlled firewall' },
    included_change_set_ids: [],
    pending_change_evidence: {},
    device_results: [],
    revision: 1,
    created_at: now,
    updated_at: now,
  };
  let state = 'DEPLOYED';
  let uncertain = false;
  await page.route('**/api/v1/deployments', async (route) => {
    await route.fulfill({
      json: [
        {
          ...base,
          id: 'controlled-batch',
          state,
          external_operation_id: state === 'DEPLOYED' ? 'domain:job' : null,
          plan_snapshot: state === 'RECONCILIATION_REQUIRED' ? { start_intent: true } : {},
          failure_info:
            state === 'DEPLOYED' || (state === 'RECONCILIATION_REQUIRED' && !uncertain)
              ? {}
              : {
                  code:
                    state === 'FAILED'
                      ? 'DEPLOYMENT_SCOPE_UNPROVEN'
                      : 'PROVIDER_DEPLOYMENT_START_UNCERTAIN',
                },
        },
      ],
    });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Deployments', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Deployments' })).toBeVisible();
  await page.getByRole('button', { name: 'View details', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Deployment details' });
  await expect(dialog.getByText('domain:job', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Retry', exact: true })).toHaveCount(0);
  state = 'RECONCILIATION_REQUIRED';
  await expect(page.getByText('Deploying', { exact: true })).toBeVisible({ timeout: 10000 });
  state = 'FAILED';
  await expect(dialog.getByText('DEPLOYMENT_SCOPE_UNPROVEN', { exact: true })).toBeVisible({
    timeout: 10000,
  });
  await expect(dialog.getByText(/Pending provider changes could not be attributed/)).toBeVisible();
  state = 'RECONCILIATION_REQUIRED';
  uncertain = true;
  await expect(dialog.getByText(/The provider outcome is uncertain/)).toBeVisible({
    timeout: 10000,
  });
  await expect(page.getByRole('button', { name: 'Retry', exact: true })).toHaveCount(0);
});
