import type { components } from './schema';

export type Session = components['schemas']['SessionResponse'];
export type ProviderSummary = components['schemas']['ProviderSummary'];
export type Overview = components['schemas']['OverviewResponse'];
export type Manager = components['schemas']['ManagerResponse'];
export type Policy = components['schemas']['PolicyResponse'];
export type Rule = components['schemas']['RuleResponse'];
export type FirewallObject = components['schemas']['ObjectResponse'];
export type ProviderStatus = components['schemas']['ProviderStatusResponse'];
export interface SynchronizationDiscrepancy {
  id: string;
  manager_id: string;
  connection_id: string | null;
  provider: 'fmc' | 'scc';
  name: string;
  policy_id: string | null;
  provider_only: boolean;
  resource_type: string;
  resource_id: string;
  state: string;
  previous_fingerprint: string | null;
  observed_fingerprint: string | null;
  previous_snapshot: Record<string, unknown>;
  observed_snapshot: Record<string, unknown>;
  details: Record<string, unknown>;
  created_at: string;
}
export type ActiveGroup = components['schemas']['ActiveGroupResponse'];
export type DelegatedPolicy = components['schemas']['DelegatedPolicySummary'];
export type DelegatedContext = components['schemas']['DelegatedContextResponse'];
export type AdministrationSnapshot = components['schemas']['AdministrationSnapshotResponse'];
export type ChangeSet = components['schemas']['ChangeSetResponse'];
export interface PendingApprovals {
  count: number;
  items: ChangeSet[];
}
export interface Deployment {
  id: string;
  organization_id: string;
  provider_transaction_id: string;
  provider_connection_id: string | null;
  state: string;
  external_operation_id: string | null;
  rollback_state: string | null;
  rollback_external_operation_id: string | null;
  rollback_requested_by_user_id: string | null;
  rollback_device_results: Array<Record<string, unknown>>;
  rollback_failure_info: Record<string, unknown>;
  rollback_eligible: boolean;
  rollback_unavailable_reason: string | null;
  requested_by_user_id: string | null;
  approved_by_user_id: string | null;
  target_device_ids: string[];
  device_names: Record<string, string>;
  included_change_set_ids: string[];
  plan_snapshot: Record<string, unknown>;
  pending_change_evidence: Record<string, unknown>;
  device_results: Array<Record<string, unknown>>;
  failure_info: Record<string, unknown>;
  revision: number;
  created_at: string;
  updated_at: string;
}
type ErrorEnvelope = components['schemas']['ErrorEnvelope'];

export class ApiError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly correlationId: string,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

const developmentUserKey = 'firewall-manager.dev-user';
const defaultDevelopmentUser = import.meta.env.VITE_DEV_AUTH_USER ?? 'viewer@example.test';

export interface DevelopmentIdentity {
  email: string;
  display_name: string;
  role: string;
  enabled: boolean;
}

export interface ProviderConnectionScope {
  id: string;
  native_id: string;
  name: string;
  scope_type: string;
  last_seen_at: string;
}

export interface ProviderCapabilityEvidence {
  capability: string;
  status: string;
  evidence_level: string;
  provider_version: string;
  tested_at: string | null;
}

export interface ProviderConnection {
  id: string;
  provider_type: 'fmc' | 'scc';
  display_name: string;
  lifecycle: 'ACTIVE' | 'DISABLED' | 'RETIRED';
  enabled: boolean;
  connection_mode: string;
  evidence_profile: 'real';
  base_endpoint: string | null;
  region: string | null;
  tls_mode: 'SYSTEM' | 'CUSTOM_CA';
  credential_present: boolean;
  credential_type: string;
  credential_username: string | null;
  credential_updated_at: string;
  provider_version: string | null;
  connection_status: string;
  sync_status: string | null;
  last_connection_test: string | null;
  last_successful_connection: string | null;
  last_sync: string | null;
  last_successful_sync: string | null;
  last_error_code: string | null;
  last_error_message: string | null;
  last_error_correlation_id: string | null;
  certificate_info: Record<string, string>;
  sync_interval_minutes: number;
  applications_sync_interval_minutes: number;
  applications_sync_status: string | null;
  applications_last_sync: string | null;
  applications_last_successful_sync: string | null;
  applications_next_sync_at: string | null;
  deployment_schedule_enabled: boolean;
  deployment_status: string | null;
  deployment_next_at: string | null;
  deployment_last_started_at: string | null;
  deployment_last_completed_at: string | null;
  write_enabled: boolean;
  write_validation_mode: boolean;
  version_family_tested: boolean;
  compatibility_warning: string | null;
  write_enabled_at: string | null;
  write_enabled_by_user_id: string | null;
  scopes: ProviderConnectionScope[];
  capability_evidence: ProviderCapabilityEvidence[];
  revision: number;
}

export interface ProviderGuidance {
  title: string;
  capability_target: string;
  steps: string[];
  permission_note: string;
  operations: Array<{ operation: string; method: string; permission: string }>;
  official_references: Array<{ label: string; url: string }>;
}

export function getDevelopmentUser(): string {
  return window.sessionStorage.getItem(developmentUserKey) ?? defaultDevelopmentUser;
}

export function switchDevelopmentUser(email: string): void {
  window.sessionStorage.setItem(developmentUserKey, email);
  Object.keys(window.sessionStorage)
    .filter((key) => key.startsWith('firewall-manager.active-context.'))
    .forEach((key) => window.sessionStorage.removeItem(key));
  // A navigation is the cache boundary: Group selection and all user-specific React state die here.
  window.location.reload();
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Dev-User': getDevelopmentUser(),
      ...init?.headers,
    },
    credentials: 'same-origin',
  });
  if (!response.ok) {
    const payload = (await response.json()) as ErrorEnvelope;
    throw new ApiError(
      payload.error.message,
      payload.error.code,
      payload.error.correlation_id,
      payload.error.details,
    );
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function get<T>(path: string): Promise<T> {
  return request<T>(path);
}

export async function loadInitialOverview(): Promise<{ session: Session; overview: Overview }> {
  const [session, overview] = await Promise.all([
    get<Session>('/api/v1/session'),
    get<Overview>('/api/v1/overview'),
  ]);
  return { session, overview };
}

export async function loadDevelopmentIdentities(): Promise<DevelopmentIdentity[]> {
  return get<DevelopmentIdentity[]>('/api/v1/dev/users');
}

export async function loadProviderConnections(): Promise<ProviderConnection[]> {
  const page = await get<{ items: ProviderConnection[]; total: number }>(
    '/api/v1/admin/provider-connections?limit=100',
  );
  return page.items;
}

export async function loadProviderGuidance(provider: 'fmc' | 'scc'): Promise<ProviderGuidance> {
  return get<ProviderGuidance>(`/api/v1/admin/provider-connections/guidance/${provider}`);
}

export async function createProviderConnection(
  values: Record<string, unknown>,
): Promise<ProviderConnection> {
  return request<ProviderConnection>('/api/v1/admin/provider-connections', {
    method: 'POST',
    body: JSON.stringify(values),
  });
}

export async function testProviderConnection(
  connectionId: string,
): Promise<{ status: string; connection: ProviderConnection }> {
  return request<{ status: string; connection: ProviderConnection }>(
    `/api/v1/admin/provider-connections/${encodeURIComponent(connectionId)}/test`,
    { method: 'POST', body: '{}' },
  );
}

export async function setProviderConnectionLifecycle(
  connection: ProviderConnection,
  lifecycle: 'ACTIVE' | 'DISABLED' | 'RETIRED',
): Promise<ProviderConnection> {
  return request<ProviderConnection>(
    `/api/v1/admin/provider-connections/${encodeURIComponent(connection.id)}/lifecycle`,
    {
      method: 'PUT',
      body: JSON.stringify({ expected_revision: connection.revision, lifecycle }),
    },
  );
}

export async function setProviderConnectionWriteGate(
  connection: ProviderConnection,
  enabled: boolean,
  allowUnvalidatedNonProduction = false,
): Promise<ProviderConnection> {
  return request<ProviderConnection>(
    `/api/v1/admin/provider-connections/${encodeURIComponent(connection.id)}/write-gate`,
    {
      method: 'PUT',
      body: JSON.stringify({
        expected_revision: connection.revision,
        enabled,
        acknowledge_configuration_mutation: enabled,
        acknowledge_unvalidated_non_production_writes: enabled && allowUnvalidatedNonProduction,
      }),
    },
  );
}

export async function requestProviderSync(
  connectionId: string,
  mode: 'FULL' | 'NON_APPLICATIONS' | 'APPLICATIONS' = 'FULL',
): Promise<void> {
  await request(
    `/api/v1/admin/provider-connections/${encodeURIComponent(connectionId)}/sync?mode=${mode}`,
    {
      method: 'POST',
      body: '{}',
    },
  );
}

export async function rotateProviderCredential(
  connection: ProviderConnection,
  values: Record<string, unknown>,
): Promise<ProviderConnection> {
  return request<ProviderConnection>(
    `/api/v1/admin/provider-connections/${encodeURIComponent(connection.id)}/credentials`,
    {
      method: 'PUT',
      body: JSON.stringify({ expected_revision: connection.revision, ...values }),
    },
  );
}

export async function updateProviderConnection(
  connection: ProviderConnection,
  values: Record<string, unknown>,
): Promise<ProviderConnection> {
  return request<ProviderConnection>(
    `/api/v1/admin/provider-connections/${encodeURIComponent(connection.id)}/configuration`,
    {
      method: 'PATCH',
      body: JSON.stringify({ expected_revision: connection.revision, ...values }),
    },
  );
}

export async function forceProviderDeployment(
  connectionId: string,
): Promise<ProviderConnection | { status: string; connection_id: string }> {
  return request<ProviderConnection | { status: string; connection_id: string }>(
    `/api/v1/admin/provider-connections/${encodeURIComponent(connectionId)}/deploy`,
    { method: 'POST', body: '{}' },
  );
}

export async function loadDelegatedPolicies(activeGroupId: string): Promise<DelegatedPolicy[]> {
  return get<DelegatedPolicy[]>(
    `/api/v1/delegated/policies?active_group_id=${encodeURIComponent(activeGroupId)}`,
  );
}

export async function loadDelegatedContext(
  activeGroupId: string,
  policyId: string,
  includeApplications = true,
  includeRules = true,
): Promise<DelegatedContext> {
  return get<DelegatedContext>(
    `/api/v1/delegated/context?active_group_id=${encodeURIComponent(activeGroupId)}&policy_id=${encodeURIComponent(policyId)}&include_applications=${includeApplications}&include_rules=${includeRules}`,
  );
}

export async function setDefaultDelegatedContext(
  groupId: string,
  policyId: string,
): Promise<{ group_id: string; policy_id: string }> {
  return request('/api/v1/session/default-context', {
    method: 'PUT',
    body: JSON.stringify({ group_id: groupId, policy_id: policyId }),
  });
}

export async function loadAdministration(): Promise<AdministrationSnapshot> {
  return get<AdministrationSnapshot>('/api/v1/admin/authorization');
}

export async function createAdministrativeResource(
  resource: 'users' | 'groups',
  values: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>(`/api/v1/admin/${resource}`, {
    method: 'POST',
    body: JSON.stringify(values),
  });
}

export async function upsertAuthorizationResource(
  resource: string,
  values: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>(`/api/v1/admin/${resource}`, {
    method: 'PUT',
    body: JSON.stringify(values),
  });
}

export async function updateAdministrativeEnabled(
  resource: 'users' | 'groups',
  resourceId: string,
  enabled: boolean,
  expectedRevision: number,
): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>(
    `/api/v1/admin/${resource}/${encodeURIComponent(resourceId)}`,
    {
      method: 'PATCH',
      body: JSON.stringify({ enabled, expected_revision: expectedRevision }),
    },
  );
}

export async function updateGroupApproval(
  groupId: string,
  approvalRequired: boolean,
  expectedRevision: number,
): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>(
    `/api/v1/admin/groups/${encodeURIComponent(groupId)}/approval`,
    {
      method: 'PATCH',
      body: JSON.stringify({
        approval_required: approvalRequired,
        expected_revision: expectedRevision,
      }),
    },
  );
}

export async function updateAdministrativeUserRole(
  userId: string,
  role: string,
  expectedRevision: number,
): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>(
    `/api/v1/admin/users/${encodeURIComponent(userId)}/role`,
    {
      method: 'PATCH',
      body: JSON.stringify({ role, expected_revision: expectedRevision }),
    },
  );
}

export async function revokeAuthorizationResource(
  resource: string,
  resourceId: string,
  expectedRevision: number,
): Promise<void> {
  await request<void>(
    `/api/v1/admin/${encodeURIComponent(resource)}/${encodeURIComponent(resourceId)}?expected_revision=${expectedRevision}`,
    { method: 'DELETE' },
  );
}

export async function loadChangeSets(activeGroupId: string): Promise<ChangeSet[]> {
  return get<ChangeSet[]>(
    `/api/v1/changesets?active_group_id=${encodeURIComponent(activeGroupId)}`,
  );
}

export async function loadPendingApprovals(): Promise<PendingApprovals> {
  return get<PendingApprovals>('/api/v1/approvals/pending');
}

export async function loadAdminChangeSets(): Promise<ChangeSet[]> {
  return get<ChangeSet[]>('/api/v1/admin/changesets');
}

export async function deleteAdminChangeSet(changeSetId: string): Promise<void> {
  await request<void>(`/api/v1/admin/changesets/${encodeURIComponent(changeSetId)}`, {
    method: 'DELETE',
  });
}

export async function deleteChangeSet(activeGroupId: string, changeSetId: string): Promise<void> {
  await request<void>(
    `/api/v1/changesets/${encodeURIComponent(changeSetId)}?active_group_id=${encodeURIComponent(activeGroupId)}`,
    { method: 'DELETE' },
  );
}

export async function createChangeSet(
  activeGroupId: string,
  policyId: string,
  title: string,
  description: string,
): Promise<ChangeSet> {
  return request<ChangeSet>('/api/v1/changesets', {
    method: 'POST',
    body: JSON.stringify({
      active_group_id: activeGroupId,
      policy_id: policyId,
      title,
      description,
    }),
  });
}

export async function addDraftRule(
  changeSetId: string,
  activeGroupId: string,
  rule: Record<string, unknown>,
  kind: 'CREATE_RULE' | 'MODIFY_RULE' | 'DELETE_RULE' | 'MOVE_RULE' = 'CREATE_RULE',
): Promise<ChangeSet> {
  return request<ChangeSet>(
    `/api/v1/changesets/${encodeURIComponent(changeSetId)}/operations/rules`,
    {
      method: 'POST',
      body: JSON.stringify({ active_group_id: activeGroupId, kind, rule }),
    },
  );
}

export async function addDraftCategory(
  changeSetId: string,
  activeGroupId: string,
  policyId: string,
): Promise<ChangeSet> {
  return request<ChangeSet>(
    `/api/v1/changesets/${encodeURIComponent(changeSetId)}/operations/categories`,
    {
      method: 'POST',
      body: JSON.stringify({ active_group_id: activeGroupId, policy_id: policyId }),
    },
  );
}

export async function addDraftObject(
  changeSetId: string,
  activeGroupId: string,
  object: Record<string, unknown>,
): Promise<ChangeSet> {
  return request<ChangeSet>(
    `/api/v1/changesets/${encodeURIComponent(changeSetId)}/operations/objects`,
    {
      method: 'POST',
      body: JSON.stringify({ active_group_id: activeGroupId, object }),
    },
  );
}

export async function changeSetAction(
  changeSetId: string,
  activeGroupId: string,
  action: 'preflight' | 'refresh' | 'execute' | 'retry' | 'cancel' | 'approve',
): Promise<ChangeSet> {
  return request<ChangeSet>(`/api/v1/changesets/${encodeURIComponent(changeSetId)}/${action}`, {
    method: 'POST',
    body: JSON.stringify({ active_group_id: activeGroupId }),
  });
}

export async function approveChangeSet(
  changeSetId: string,
  activeGroupId: string,
): Promise<ChangeSet> {
  return changeSetAction(changeSetId, activeGroupId, 'approve');
}

export async function loadDeployments(): Promise<Deployment[]> {
  return get<Deployment[]>('/api/v1/deployments');
}

export async function loadDeploymentChangeSets(deploymentId: string): Promise<ChangeSet[]> {
  return get<ChangeSet[]>(
    `/api/v1/deployments/${encodeURIComponent(deploymentId)}/changesets`,
  );
}

export async function retryDeployment(
  deploymentId: string,
): Promise<Deployment | { status: string; connection_id: string }> {
  return request<Deployment | { status: string; connection_id: string }>(
    `/api/v1/deployments/${encodeURIComponent(deploymentId)}/retry`,
    { method: 'POST', body: '{}' },
  );
}

export async function rollbackDeployment(
  deploymentId: string,
  selectedChangeSetIds: string[],
): Promise<ChangeSet[]> {
  return request<ChangeSet[]>(
    `/api/v1/deployments/${encodeURIComponent(deploymentId)}/rollback`,
    { method: 'POST', body: JSON.stringify({ selected_change_set_ids: selectedChangeSetIds }) },
  );
}

export interface Inventory {
  managers: Manager[];
  policies: Policy[];
  rules: Rule[];
  objects: FirewallObject[];
  statuses: ProviderStatus[];
  discrepancies: SynchronizationDiscrepancy[];
}

export async function loadSynchronizationDiscrepancies(): Promise<SynchronizationDiscrepancy[]> {
  return get<SynchronizationDiscrepancy[]>('/api/v1/synchronization/discrepancies');
}

export async function acceptProviderState(driftId: string): Promise<{ id: string; state: string }> {
  return request<{ id: string; state: string }>(
    `/api/v1/synchronization/discrepancies/${encodeURIComponent(driftId)}/accept-provider-state`,
    { method: 'POST', body: '{}' },
  );
}

export async function restoreProviderState(
  driftId: string,
  activeGroupId: string,
): Promise<{ action: string; drift_id: string; state: string; change_set_id: string | null }> {
  return request(
    `/api/v1/synchronization/discrepancies/${encodeURIComponent(driftId)}/restore-proposal`,
    {
      method: 'POST',
      body: JSON.stringify({ active_group_id: activeGroupId }),
    },
  );
}

export async function loadInventory(): Promise<Inventory> {
  const [policyPage, rulePage, objectPage, statuses] = await Promise.all([
    get<components['schemas']['PageResponse_PolicyResponse_']>('/api/v1/policies?limit=100'),
    get<components['schemas']['PageResponse_RuleResponse_']>('/api/v1/rules?limit=100'),
    get<components['schemas']['PageResponse_ObjectResponse_']>('/api/v1/objects?limit=100'),
    get<ProviderStatus[]>('/api/v1/providers/status'),
  ]);
  return {
    // Sync & drift does not render manager inventory; provider status is its source of truth.
    managers: [],
    policies: policyPage.items,
    rules: rulePage.items,
    objects: objectPage.items,
    statuses,
    discrepancies: [],
  };
}
