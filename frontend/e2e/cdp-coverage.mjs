// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

const root = process.cwd();
const reportDir = process.env.E2E_COVERAGE_DIR ?? '/tmp/firewall-manager-cdp-coverage';
const fullDir = join(reportDir, 'full');
const routeDir = join(reportDir, 'routes');
const faultDir = join(reportDir, 'faults');
mkdirSync(reportDir, { recursive: true });

const expectedRoutes = [
  'home',
  'policies',
  'rules',
  'objects',
  'changes',
  'users',
  'groups',
  'grants',
  'identity-providers',
  'providers',
  'sync',
  'changesets-admin',
  'deployments',
  'audit',
  'approvals',
];
const expectedFaults = [
  'login-unauthenticated.png',
  'login-no-provider.png',
  'application-api-error.png',
];

function run(command, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: root,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

function finalJSON(stdout) {
  const trimmed = stdout.trim();
  const startsAtZero = trimmed.startsWith('{');
  const start = startsAtZero ? 0 : trimmed.lastIndexOf('\n{');
  if (start < 0) throw new Error('CDP runner did not emit a JSON result');
  return JSON.parse(trimmed.slice(startsAtZero ? start : start + 1));
}

function requirePass(result, label) {
  if (result.code !== 0) throw new Error(`${label} failed:\n${result.stderr || result.stdout}`);
}

function requireFiles(directory, names, label) {
  const missing = names.filter(
    (name) => !existsSync(join(directory, `${name}.png`)) && !existsSync(join(directory, name)),
  );
  if (missing.length) throw new Error(`${label} missing evidence: ${missing.join(', ')}`);
}

async function main() {
  const runs = {};
  runs.full = await run('node', ['e2e/cdp-application-sweep.mjs'], {
    E2E_APPLICATION_SCREENSHOT_DIR: fullDir,
  });
  requirePass(runs.full, 'full CDP state sweep');
  const full = finalJSON(runs.full.stdout);
  if (
    full.screens.length !== expectedRoutes.length ||
    expectedRoutes.some((route) => !full.screens.includes(route))
  ) {
    throw new Error(`Full CDP route coverage mismatch: ${JSON.stringify(full.screens)}`);
  }
  if (full.events.length)
    throw new Error(`Full CDP runtime events: ${JSON.stringify(full.events)}`);

  runs.routes = await run('node', ['e2e/cdp-route-smoke.mjs'], {
    E2E_ROUTE_SCREENSHOT_DIR: routeDir,
  });
  requirePass(runs.routes, 'route/accessibility CDP sweep');
  const routes = finalJSON(runs.routes.stdout);
  if (routes.routes.length !== expectedRoutes.length)
    throw new Error('Route sweep did not cover all navigation routes');
  if (routes.events.length || routes.a11y.some((item) => item.violations.length)) {
    throw new Error(
      `Route sweep reported failures: ${JSON.stringify({ events: routes.events, a11y: routes.a11y })}`,
    );
  }

  runs.functions = await run('node', ['e2e/cdp-function-smoke.mjs']);
  requirePass(runs.functions, 'function CDP sweep');
  const functions = finalJSON(runs.functions.stdout);
  const unavailable = functions.tested.filter(([, passed]) => !passed);
  if (unavailable.length || functions.events.length) {
    throw new Error(
      `Function coverage incomplete: ${JSON.stringify({ unavailable, events: functions.events })}`,
    );
  }

  runs.faults = await run('node', ['e2e/cdp-fault-smoke.mjs'], {
    E2E_FAULT_SCREENSHOT_DIR: faultDir,
  });
  requirePass(runs.faults, 'fault/entry-state CDP sweep');
  const faults = finalJSON(runs.faults.stdout);
  requireFiles(faultDir, expectedFaults, 'fault/entry-state');

  const report = {
    status: 'PASS',
    route_count: expectedRoutes.length,
    authenticated_screenshot_directory: fullDir,
    route_screenshot_directory: routeDir,
    fault_screenshot_directory: faultDir,
    authenticated_screenshot_count: readdirSync(fullDir).filter((name) => name.endsWith('.png'))
      .length,
    fault_screenshot_count: faults.results.length,
    function_check_count: functions.tested.length,
    function_checks: functions.tested.map(([name, passed]) => ({ name, passed })),
    runtime_events: [],
  };
  writeFileSync(join(reportDir, 'cdp-coverage.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

main().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : error);
  process.exitCode = 1;
});
