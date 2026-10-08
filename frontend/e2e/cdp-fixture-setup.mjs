// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { chromium } from 'playwright';

const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:5173';
const endpoint = process.env.E2E_CDP_ENDPOINT ?? 'http://127.0.0.1:9222';
const screenshotDir =
  process.env.E2E_APPLICATION_SCREENSHOT_DIR ?? '/tmp/firewall-manager-cdp-application';
const fixture = {
  group: 'CDP Approval Test Group',
  prefix: 'CDPTEST',
  email: 'cdp-test-operator@example.test',
};
const approvalRunId = process.env.E2E_APPROVAL_RUN_ID ?? String(Date.now());
const approvalObject = `CDP_APPROVAL_NETWORK_${approvalRunId}`;
const approvalChangeSet = `CDP approval ChangeSet ${approvalRunId}`;

async function waitSettled(page) {
  const status = page.locator('[role="status"]');
  if (await status.count())
    await status
      .first()
      .waitFor({ state: 'detached', timeout: 20_000 })
      .catch(() => {});
  await page
    .getByText('Recalculating Group and policy access', { exact: true })
    .waitFor({ state: 'detached', timeout: 30_000 })
    .catch(() => {});
  await page.waitForTimeout(300);
}

async function nav(page, label, heading) {
  await page.getByRole('button', { name: label, exact: true }).click();
  await page
    .getByRole('heading', { name: heading, exact: true })
    .first()
    .waitFor({ timeout: 20_000 });
  await waitSettled(page);
}

async function closeDialog(page) {
  const dialog = page.getByRole('dialog').last();
  if (await dialog.count()) {
    const close = dialog.getByRole('button', { name: /^(Cancel|Close|Done|Back)$/i }).last();
    if (await close.count()) await close.click({ force: true });
    else await page.keyboard.press('Escape');
  }
  await page.waitForTimeout(200);
}

async function chooseFirst(scope, page, label) {
  const field = scope.getByLabel(label, { exact: false });
  await field.click({ force: true });
  const option = page.getByRole('option').first();
  await option.waitFor({ timeout: 5_000 });
  const value = await option.innerText();
  await option.click();
  return value;
}

async function chooseNamed(scope, page, label, name) {
  const field = scope.getByLabel(label, { exact: false });
  await field.click({ force: true });
  const option = page.getByRole('option', { name, exact: true });
  await option.waitFor({ timeout: 5_000 });
  await option.click();
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
    if (response.status() >= 400) {
      void response
        .text()
        .then((body) =>
          events.push(`http ${response.status()}: ${response.url()} ${body.slice(0, 300)}`),
        )
        .catch(() => events.push(`http ${response.status()}: ${response.url()}`));
    }
  });
  page.on('console', (message) => {
    if (['error', 'warning'].includes(message.type()))
      events.push(`console ${message.type()}: ${message.text()}`);
  });
  page.on('dialog', async (dialog) => {
    try {
      await dialog.accept();
    } catch {}
  });

  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Security posture' }).waitFor({ timeout: 20_000 });
  const result = { fixture, created: [], reused: [], grants: [], events };

  await nav(page, 'Groups', 'Groups');
  const groupRow = page.locator('tbody tr').filter({ hasText: fixture.group }).first();
  if (await groupRow.count()) result.reused.push('group');
  else {
    await page.getByRole('button', { name: 'Create Group', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Create Group' });
    await dialog.getByLabel('Group name', { exact: false }).fill(fixture.group);
    await dialog.getByLabel('Stable provider prefix', { exact: false }).fill(fixture.prefix);
    await dialog.getByLabel('Require ChangeSet approval', { exact: false }).check();
    await dialog.getByRole('button', { name: 'Create Group', exact: true }).click();
    await dialog.waitFor({ state: 'hidden', timeout: 20_000 });
    result.created.push('group');
  }

  await nav(page, 'Users', 'Users');
  const userRow = page.locator('tbody tr').filter({ hasText: fixture.email }).first();
  if (await userRow.count()) result.reused.push('user');
  else {
    await page.getByRole('button', { name: 'Create User', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Create User' });
    await dialog.getByLabel('Display name', { exact: false }).fill('CDP Test Operator');
    await dialog.getByLabel('Email address', { exact: false }).fill(fixture.email);
    await dialog
      .getByLabel('External identity issuer', { exact: false })
      .fill('urn:firewall-manager:development');
    await dialog.getByLabel('External subject (sub)', { exact: false }).fill(fixture.email);
    await dialog.getByRole('button', { name: 'Create User', exact: true }).click();
    await dialog.waitFor({ state: 'hidden', timeout: 20_000 });
    result.created.push('user');
  }

  await nav(page, 'Groups', 'Groups');
  const currentGroup = page.locator('tbody tr').filter({ hasText: fixture.group }).first();
  await currentGroup.getByRole('button', { name: 'Manage members', exact: true }).click();
  const membership = page.getByRole('dialog', { name: 'Manage members' });
  const operator = membership
    .locator('.fm-membership-row')
    .filter({ hasText: fixture.email })
    .first();
  const add = operator.getByRole('button', { name: 'Add', exact: true });
  if (await add.count()) {
    await add.click();
    result.created.push('membership');
  } else result.reused.push('membership');
  const adminRow = membership
    .locator('.fm-membership-row')
    .filter({ hasText: 'Platform Admin' })
    .first();
  if (await adminRow.count()) {
    const adminAdd = adminRow.getByRole('button', { name: 'Add', exact: true });
    if (await adminAdd.count()) {
      await adminAdd.click();
      result.created.push('admin-membership');
    } else result.reused.push('admin-membership');
  }
  await closeDialog(page);

  await nav(page, 'Access grants', 'Access grants');
  await page.getByRole('tab', { name: 'Policy access', exact: true }).click();
  const delegation = page.getByRole('button', { name: 'Add group delegation', exact: true });
  if (await delegation.count()) {
    await delegation.click();
    const dialog = page.getByRole('dialog', { name: 'Add group policy delegation' });
    await chooseNamed(dialog, page, 'Group context', fixture.group);
    await chooseFirst(dialog, page, 'Access policy');
    const capabilities = dialog.getByLabel('Capabilities', { exact: true });
    await capabilities.click({ force: true });
    for (const capability of ['Create rules', 'Modify objects']) {
      const option = page.getByRole('option', { name: capability, exact: true });
      if (await option.count()) await option.click();
    }
    await page.keyboard.press('Escape');
    await dialog.getByRole('button', { name: 'Add access grant', exact: true }).click();
    await dialog.waitFor({ state: 'hidden', timeout: 20_000 });
    result.grants.push('group-policy-delegation');
  }

  await page.getByRole('tab', { name: 'Resource access', exact: true }).click();
  const resourceTabs = [
    ['Networks', 'Add network object access'],
    ['Ports', 'Add port object access'],
    ['URLs', 'Add URL object access'],
    ['Applications', 'Add application object access'],
    ['Zones', 'Add security zone access'],
    ['IP ranges', 'Add authorized IP range'],
    ['Creation', 'Add object creation right'],
  ];
  for (const [tab, addLabel] of resourceTabs) {
    await page.getByRole('tab', { name: tab, exact: true }).click();
    const addButton = page.getByRole('button', { name: addLabel, exact: true });
    if (!(await addButton.count())) continue;
    await addButton.click();
    const dialog = page.getByRole('dialog').last();
    await chooseNamed(dialog, page, 'Group context', fixture.group);
    await chooseFirst(dialog, page, 'Access policy');
    if (addLabel === 'Add authorized IP range') {
      await dialog.getByLabel('Authorized network', { exact: false }).fill('0.0.0.0/0');
    } else if (addLabel === 'Add object creation right') {
      await chooseNamed(dialog, page, 'Object type', 'Network');
    } else {
      const resource = dialog.getByLabel('Firewall object', { exact: false });
      if (await resource.count()) await chooseFirst(dialog, page, 'Firewall object');
    }
    const submit = dialog.getByRole('button', { name: 'Add access grant', exact: true });
    if ((await submit.count()) && (await submit.isEnabled())) {
      await submit.click();
      const closed = await dialog
        .waitFor({ state: 'hidden', timeout: 20_000 })
        .then(() => true)
        .catch(() => false);
      if (closed) result.grants.push(addLabel);
      else {
        result.grants.push(`${addLabel}:rejected`);
        await closeDialog(page);
      }
    } else await closeDialog(page);
  }

  await page.getByRole('tab', { name: 'Category mappings', exact: true }).click();
  const categoryAdd = page.getByRole('button', { name: 'Add category mapping', exact: true });
  if (await categoryAdd.count()) {
    await categoryAdd.click();
    const dialog = page.getByRole('dialog').last();
    await chooseNamed(dialog, page, 'Group context', fixture.group);
    await chooseFirst(dialog, page, 'Access policy');
    const category = dialog.getByLabel('Provider category', { exact: false });
    let categoryAvailable = true;
    if (await category.count()) {
      try {
        await chooseFirst(dialog, page, 'Provider category');
      } catch {
        categoryAvailable = false;
      }
    }
    if (!categoryAvailable) {
      result.grants.push('Add category mapping:unavailable');
      await closeDialog(page);
    } else {
      const expected = dialog.getByLabel('Expected provider category name', { exact: false });
      if (await expected.count()) await expected.fill('CDPTEST__TEST');
      const submit = dialog.getByRole('button', { name: 'Add access grant', exact: true });
      if ((await submit.count()) && (await submit.isEnabled())) {
        await submit.click();
        const closed = await dialog
          .waitFor({ state: 'hidden', timeout: 20_000 })
          .then(() => true)
          .catch(() => false);
        result.grants.push(closed ? 'Add category mapping' : 'Add category mapping:rejected');
        if (!closed) await closeDialog(page);
      } else await closeDialog(page);
    }
  }

  await page.setExtraHTTPHeaders({ 'X-Dev-User': fixture.email });
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Security posture' }).waitFor({ timeout: 20_000 });
  await nav(page, 'Policies', 'Policy browser');
  const mapping = page.locator('tbody tr').filter({ hasText: fixture.group }).first();
  if (await mapping.count()) {
    const select = mapping.getByRole('button', { name: 'Select', exact: true });
    if (await select.count()) await select.click();
    await waitSettled(page);
    await page.waitForTimeout(1_000);
    await page
      .getByText(fixture.group, { exact: true })
      .first()
      .waitFor({ timeout: 10_000 })
      .catch(() => {});
    result.created.push('delegated-context-selected');
  }

  await nav(page, 'Objects', 'Object inventory');
  const existingObject = page.locator('tbody tr').filter({ hasText: approvalObject }).first();
  if (await existingObject.count()) result.reused.push('approval-object');
  else {
    const create = page.getByRole('button', { name: 'Create object', exact: true });
    await create.waitFor({ timeout: 20_000 }).catch(() => {});
    if (await create.count()) {
      await create.click();
      const dialog = page.getByRole('dialog', { name: 'Create firewall object' });
      await dialog.getByLabel('ChangeSet name', { exact: false }).fill(approvalChangeSet);
      await chooseFirst(dialog, page, 'Object type');
      await dialog.getByLabel('Object name', { exact: false }).fill(approvalObject);
      await dialog.getByLabel('Value', { exact: false }).fill('10.30.10.30/32');
      const addObject = dialog.getByRole('button', {
        name: 'Add object to ChangeSet',
        exact: true,
      });
      if (!(await addObject.isEnabled())) {
        await page.screenshot({
          path: `${screenshotDir}/approval-object-unavailable.png`,
          fullPage: true,
        });
        const selectedType = await dialog
          .getByLabel('Object type', { exact: false })
          .inputValue()
          .catch(() => 'unknown');
        result.created.push(
          `approval-object-unavailable:${selectedType}:${(await dialog.innerText()).slice(0, 240)}`,
        );
        await closeDialog(page);
        result.events = events;
        console.log(JSON.stringify(result, null, 2));
        await page.close();
        await browser.close();
        return;
      }
      await addObject.click();
      await dialog.getByRole('button', { name: /Review 1 object/, exact: true }).click();
      await page.waitForTimeout(1_000);
      const approvalState = await dialog.getByText(/approval|required|ready/i).allTextContents();
      result.created.push(`approval-changeset:${approvalState.join(' ').slice(0, 160)}`);
      const execute = dialog.getByRole('button', {
        name: /Create 1 object on provider/,
        exact: true,
      });
      if ((await execute.count()) && (await execute.isEnabled())) {
        await execute.click();
        result.created.push('approval-object-executed');
      } else result.created.push('approval-object-awaiting-approval');
      await closeDialog(page);
    } else result.created.push('approval-object-control-unavailable');
  }

  await page.setExtraHTTPHeaders({ 'X-Dev-User': 'admin@example.test' });
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Security posture' }).waitFor({ timeout: 20_000 });
  await nav(page, 'Pending approvals', 'Pending approvals');
  const pending = page.locator('tbody tr').filter({ hasText: approvalChangeSet }).first();
  if (await pending.count()) {
    const approve = pending.getByRole('button', { name: 'Approve', exact: true });
    if (await approve.count()) {
      await approve.click();
      await page.waitForTimeout(1_000);
      result.created.push('approval-approved');
    }
  } else result.created.push('approval-pending-not-visible-to-admin');

  await nav(page, 'All ChangeSets', 'All ChangeSets');
  const fixtureChangeSet = page
    .getByRole('listitem')
    .filter({ hasText: approvalChangeSet })
    .first();
  if (await fixtureChangeSet.count()) {
    const execute = fixtureChangeSet.getByRole('button', { name: 'Execute', exact: true });
    if (await execute.count()) {
      // The confirmation is still exercised by the browser, but overriding it here
      // keeps the repeatable CDP harness from racing the native dialog event.
      await page.evaluate(() => {
        window.confirm = () => true;
      });
      await execute.click();
      await page.waitForTimeout(1_000);
      const stateText = (await fixtureChangeSet.innerText()).slice(0, 240);
      result.created.push(
        stateText.includes('QUEUED')
          ? 'approval-changeset-execution-requested'
          : 'approval-changeset-execution-not-queued',
      );
      result.created.push(`approval-changeset-state:${stateText}`);
      let terminalState = stateText;
      for (let attempt = 0; attempt < 18 && !/SUCCEEDED|FAILED/.test(terminalState); attempt += 1) {
        await page.waitForTimeout(5_000);
        await page.reload({ waitUntil: 'domcontentloaded' });
        const allChangeSets = page.getByRole('button', { name: 'All ChangeSets', exact: true });
        if (!(await page.getByRole('heading', { name: 'All ChangeSets', exact: true }).count())) {
          await allChangeSets.click({ force: true });
        }
        await page
          .getByRole('heading', { name: 'All ChangeSets', exact: true })
          .waitFor({ timeout: 20_000 });
        terminalState = await page
          .getByRole('listitem')
          .filter({ hasText: approvalChangeSet })
          .first()
          .innerText();
      }
      if (terminalState.includes('SUCCEEDED')) result.created.push('approval-changeset-succeeded');
      else if (terminalState.includes('FAILED')) result.created.push('approval-changeset-failed');
      else result.created.push('approval-changeset-terminal-state-timeout');
      result.created.push(`approval-changeset-final-state:${terminalState.slice(0, 240)}`);
    } else result.created.push('approval-changeset-not-executable');
  }

  result.events = events;
  console.log(JSON.stringify(result, null, 2));
  await page.close();
  await browser.close();
}

run().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : error);
  process.exitCode = 1;
});
