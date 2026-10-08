// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { lazy, Suspense, useCallback, useEffect, useState } from 'react';
import {
  IconAlertTriangle,
  IconFileDiff,
  IconPackages,
  IconPlugConnected,
  IconShieldCheck,
} from '@tabler/icons-react';

import {
  loadDelegatedPolicies,
  loadChangeSets,
  loadPendingApprovals,
  exitProxySession,
  logout,
  type Overview,
  type Session,
} from '../../api/client';
import { DevelopmentUserSelector } from '../auth/DevelopmentUserSelector';
import { LoginPage } from '../auth/LoginPage';
import {
  AppCard,
  AppAlert,
  AppButton,
  AppEmptyState,
  AppErrorState,
  AppGroup,
  AppLayout,
  AppLoadingState,
  AppPage,
  AppProviderBadge,
  AppSection,
  AppSimpleGrid,
  AppStack,
  AppStatusBadge,
  AppText,
  AppThemeIcon,
  MetricCard,
  type AppRoute,
} from '../../ui';
import { useOverview } from './useOverview';

const AdministrationPanel = lazy(() =>
  import('../admin/AdministrationPanel').then((module) => ({
    default: module.AdministrationPanel,
  })),
);
const ApprovalsPage = lazy(() =>
  import('../approvals/ApprovalsPage').then((module) => ({ default: module.ApprovalsPage })),
);
const DelegatedWorkspace = lazy(() =>
  import('../delegated/DelegatedWorkspace').then((module) => ({
    default: module.DelegatedWorkspace,
  })),
);
const AdminChangeSetsPanel = lazy(() =>
  import('../changesets/AdminChangeSetsPanel').then((module) => ({
    default: module.AdminChangeSetsPanel,
  })),
);
const DeploymentsPage = lazy(() =>
  import('../deployments/DeploymentsPage').then((module) => ({ default: module.DeploymentsPage })),
);
const ProviderConnectionsPanel = lazy(() =>
  import('../provider-connections/ProviderConnectionsPanel').then((module) => ({
    default: module.ProviderConnectionsPanel,
  })),
);
const SyncDriftPage = lazy(() =>
  import('../operations/OperationsPages').then((module) => ({ default: module.SyncDriftPage })),
);
const AuditPage = lazy(() =>
  import('../operations/OperationsPages').then((module) => ({ default: module.AuditPage })),
);

const REJECTION_NOTICE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

function rejectionNoticeActive(item: {
  rejected_at?: string | null;
  rejection_notice_dismissed_at?: string | null;
}) {
  if (item.rejection_notice_dismissed_at) return false;
  if (!item.rejected_at) return true;
  return Date.now() - Date.parse(item.rejected_at) < REJECTION_NOTICE_MAX_AGE_MS;
}
const IdentityProvidersPanel = lazy(() =>
  import('../admin/IdentityProvidersPanel').then((module) => ({
    default: module.IdentityProvidersPanel,
  })),
);
const SmtpSettingsPanel = lazy(() =>
  import('../admin/SmtpSettingsPanel').then((module) => ({ default: module.SmtpSettingsPanel })),
);

export function OverviewPage() {
  const query = new URLSearchParams(window.location.search);
  if (query.get('preview') === 'login') return <LoginPage />;
  const oidcTest = query.get('oidc_test');
  const authError = query.get('auth_error');
  if (oidcTest === 'success') {
    return (
      <StandaloneState>
        <AppAlert color="green">
          OIDC test successful. The provider authenticated successfully and passed validation. No
          application user session was created.
        </AppAlert>
      </StandaloneState>
    );
  }
  return <AuthenticatedOverviewPage authError={authError} />;
}

function AuthenticatedOverviewPage({ authError }: { authError: string | null }) {
  const state = useOverview();
  if (state.status === 'loading')
    return (
      <StandaloneState>
        <AppLoadingState label="Loading security control plane" />
      </StandaloneState>
    );
  if (state.status === 'error')
    return (
      <StandaloneState>
        <AppErrorState message={state.message} reference={state.correlationId} />
      </StandaloneState>
    );
  if (state.status === 'unauthenticated') {
    return (
      <LoginPage
        initialError={
          authError
            ? 'Authentication could not be completed. Try again or contact an administrator.'
            : undefined
        }
      />
    );
  }
  return <ReadyApplication overview={state.overview} session={state.session} />;
}

function StandaloneState({ children }: { children: React.ReactNode }) {
  return <div style={{ maxWidth: 720, margin: '15vh auto', padding: 24 }}>{children}</div>;
}

function ReadyApplication({ overview, session }: { overview: Overview; session: Session }) {
  const [proxyExitError, setProxyExitError] = useState<string | null>(null);
  const [proxyExiting, setProxyExiting] = useState(false);
  const [route, setRoute] = useState<AppRoute>('home');
  const [changeSetDetailsId, setChangeSetDetailsId] = useState<string>();
  const [approvalCount, setApprovalCount] = useState(0);
  const [rejectedChangeSetCount, setRejectedChangeSetCount] = useState(0);
  useEffect(() => {
    if (!['approver', 'firewall_operator', 'admin'].includes(session.role ?? '')) return;
    const refreshApprovals = () => {
      void loadPendingApprovals()
        .then((result) => setApprovalCount(result.count))
        .catch(() => undefined);
    };
    refreshApprovals();
    const timer = window.setInterval(refreshApprovals, 15_000);
    return () => window.clearInterval(timer);
  }, [session.role]);
  const storageKey = `firewall-manager.active-context.${session.user_id}`;
  const storedContext = readStoredContext(storageKey);
  const initialGroupId = session.groups.some((group) => group.id === storedContext?.groupId)
    ? storedContext?.groupId
    : (session.default_group_id ?? session.groups[0]?.id);
  const [workingContext, setWorkingContext] = useState<{
    groupId?: string;
    policyId?: string;
    group?: string;
    policy?: string;
  }>({
    groupId: initialGroupId,
    policyId:
      initialGroupId === storedContext?.groupId
        ? storedContext?.policyId
        : initialGroupId === session.default_group_id
          ? (session.default_policy_id ?? undefined)
          : undefined,
    group:
      storedContext && storedContext.groupId === initialGroupId
        ? storedContext.group
        : session.groups.find((group) => group.id === initialGroupId)?.name,
    policy:
      storedContext && storedContext.groupId === initialGroupId ? storedContext.policy : undefined,
  });
  const [defaultContext, setDefaultContext] = useState({
    groupId: session.default_group_id ?? undefined,
    policyId: session.default_policy_id ?? undefined,
  });
  useEffect(() => {
    if (!workingContext.groupId) {
      setRejectedChangeSetCount(0);
      return;
    }
    const refreshRejected = () => {
      void loadChangeSets(workingContext.groupId!)
        .then((items) =>
          setRejectedChangeSetCount(
            items.filter((item) => item.state === 'REJECTED' && rejectionNoticeActive(item)).length,
          ),
        )
        .catch(() => undefined);
    };
    refreshRejected();
    const onRejectionDismissed = () => refreshRejected();
    window.addEventListener('firewall-manager:rejection-dismissed', onRejectionDismissed);
    const timer = window.setInterval(refreshRejected, 15_000);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('firewall-manager:rejection-dismissed', onRejectionDismissed);
    };
  }, [workingContext.groupId]);
  const updateWorkingContext = useCallback(
    (groupId?: string, policyId?: string, group?: string, policy?: string) => {
      setWorkingContext((current) => {
        const next = {
          groupId,
          policyId,
          group: group ?? (current.groupId === groupId ? current.group : undefined),
          policy: policy ?? (current.policyId === policyId ? current.policy : undefined),
        };
        return current.groupId === next.groupId &&
          current.policyId === next.policyId &&
          current.group === next.group &&
          current.policy === next.policy
          ? current
          : next;
      });
    },
    [],
  );
  useEffect(() => {
    if (!workingContext.groupId || !workingContext.policyId || workingContext.policy) return;
    let current = true;
    void loadDelegatedPolicies(workingContext.groupId)
      .then((policies) => {
        if (!current) return;
        const policy = policies.find((item) => item.id === workingContext.policyId);
        if (policy) {
          setWorkingContext((context) =>
            context.groupId === workingContext.groupId && context.policyId === policy.id
              ? { ...context, policy: policy.name }
              : context,
          );
        }
      })
      .catch(() => undefined);
    return () => {
      current = false;
    };
  }, [workingContext.groupId, workingContext.policy, workingContext.policyId]);
  useEffect(() => {
    if (workingContext.groupId && workingContext.policyId) {
      window.sessionStorage.setItem(
        storageKey,
        JSON.stringify({
          groupId: workingContext.groupId,
          policyId: workingContext.policyId,
          group: workingContext.group,
          policy: workingContext.policy,
        }),
      );
    }
  }, [
    storageKey,
    workingContext.group,
    workingContext.groupId,
    workingContext.policy,
    workingContext.policyId,
  ]);
  const admin = session.role === 'admin';
  return (
    <AppLayout
      workingGroup={workingContext.group}
      workingPolicy={workingContext.policy}
      session={session}
      approvalCount={approvalCount}
      rejectedChangeSetCount={rejectedChangeSetCount}
      route={route}
      onRouteChange={(nextRoute) => setRoute(nextRoute)}
      onLogout={() => {
        void logout()
          .catch(() => undefined)
          .finally(() => {
            window.location.assign('/');
          });
      }}
      headerActions={<DevelopmentUserSelector compact />}
    >
      {session.proxied && (
        <div className="fm-proxy-banner" role="status">
          <AppThemeIcon
            className="fm-proxy-banner-icon"
            size={30}
            radius="xl"
            variant="light"
            color="orange"
          >
            <IconAlertTriangle size={16} />
          </AppThemeIcon>
          <div className="fm-proxy-banner-copy">
            <AppText size="xs" fw={750} tt="uppercase" lts=".08em">
              Proxy session active
            </AppText>
            <AppText size="sm">
              Viewing as <strong>{session.email}</strong>
              <span className="fm-proxy-banner-detail">
                {' '}
                · Actions remain attributed to your Platform Admin identity.
              </span>
            </AppText>
          </div>
          <AppButton
            className="fm-proxy-banner-action"
            size="sm"
            loading={proxyExiting}
            disabled={proxyExiting}
            onClick={() => {
              setProxyExitError(null);
              setProxyExiting(true);
              void exitProxySession()
                .then(() => {
                  window.location.replace('/');
                })
                .catch((error: unknown) => {
                  setProxyExiting(false);
                  setProxyExitError(
                    error instanceof Error ? error.message : 'Unable to exit proxy session.',
                  );
                });
            }}
          >
            Exit proxy
          </AppButton>
          {proxyExitError && (
            <AppText className="fm-proxy-banner-error" size="xs">
              {proxyExitError}
            </AppText>
          )}
        </div>
      )}
      <Suspense fallback={<AppLoadingState label="Loading workspace" />}>
        {route === 'home' && (
          <Dashboard overview={overview} onNavigate={setRoute} isAdmin={session.role === 'admin'} />
        )}
        {['policies', 'rules', 'objects', 'changes'].includes(route) && (
          <DelegatedWorkspace
            groups={session.groups}
            initialView={route as 'policies' | 'rules' | 'objects' | 'changes'}
            initialGroupId={workingContext.groupId}
            initialPolicyId={workingContext.policyId}
            defaultGroupId={defaultContext.groupId}
            defaultPolicyId={defaultContext.policyId}
            onContextChange={updateWorkingContext}
            onDefaultChange={(groupId, policyId) => setDefaultContext({ groupId, policyId })}
          />
        )}
        {route === 'providers' && admin && (
          <AppPage
            eyebrow="Infrastructure"
            title="Provider connections"
            description="Manage FMC and Security Cloud Control connectivity, synchronization, and production writes."
          >
            <ProviderConnectionsPanel />
          </AppPage>
        )}
        {['users', 'groups', 'grants'].includes(route) && admin && (
          <AppPage
            eyebrow="Access & delegation"
            title={route === 'grants' ? 'Access grants' : route[0]!.toUpperCase() + route.slice(1)}
            description={
              route === 'groups'
                ? 'Create and govern ownership groups used for provider naming and policy delegation.'
                : route === 'users'
                  ? 'Manage control-plane identities, roles, status, and Group membership.'
                  : 'Build and review policy-scoped delegations and explicit resource permissions.'
            }
          >
            <Suspense fallback={<AppLoadingState label="Loading access administration" />}>
              <AdministrationPanel view={route as 'users' | 'groups' | 'grants'} />
            </Suspense>
          </AppPage>
        )}
        {route === 'identity-providers' && admin && (
          <AppPage
            eyebrow="Access & delegation"
            title="Identity providers"
            description="Configure enterprise OIDC providers. Client secrets are encrypted and write-only."
          >
            <Suspense fallback={<AppLoadingState label="Loading identity providers" />}>
              <IdentityProvidersPanel />
            </Suspense>
          </AppPage>
        )}
        {route === 'smtp' && admin && (
          <AppPage
            eyebrow="Operations"
            title="SMTP notifications"
            description="Configure authenticated and encrypted email delivery for approval notifications."
          >
            <Suspense fallback={<AppLoadingState label="Loading SMTP settings" />}>
              <SmtpSettingsPanel />
            </Suspense>
          </AppPage>
        )}
        {route === 'changesets-admin' && admin && (
          <AppPage
            eyebrow="Operations"
            title="All Changesets"
            description="Organization-wide Changeset status and cleanup for administrators."
          >
            <AdminChangeSetsPanel initialDetailsId={changeSetDetailsId} />
          </AppPage>
        )}
        {route === 'deployments' && admin && (
          <DeploymentsPage
            onViewChangeSet={(changeSetId) => {
              setChangeSetDetailsId(changeSetId);
              setRoute('changesets-admin');
            }}
          />
        )}
        {route === 'approvals' &&
          ['approver', 'firewall_operator', 'admin'].includes(session.role ?? '') && (
            <ApprovalsPage />
          )}
        {route === 'sync' && admin && (
          <SyncDriftPage activeGroupId={workingContext.groupId ?? ''} />
        )}
        {route === 'audit' && admin && <AuditPage />}
      </Suspense>
    </AppLayout>
  );
}

function readStoredContext(
  key: string,
): { groupId: string; policyId: string; group?: string; policy?: string } | undefined {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(key) ?? 'null') as unknown;
    if (
      value &&
      typeof value === 'object' &&
      'groupId' in value &&
      typeof value.groupId === 'string' &&
      'policyId' in value &&
      typeof value.policyId === 'string'
    )
      return {
        groupId: value.groupId,
        policyId: value.policyId,
        group: 'group' in value && typeof value.group === 'string' ? value.group : undefined,
        policy: 'policy' in value && typeof value.policy === 'string' ? value.policy : undefined,
      };
  } catch {
    // Ignore stale or malformed browser state and fall back to the user's saved default.
  }
  return undefined;
}

function Dashboard({
  isAdmin,
  overview,
  onNavigate,
}: {
  overview: Overview;
  isAdmin: boolean;
  onNavigate: (route: AppRoute) => void;
}) {
  if (!isAdmin) {
    return (
      <AppPage
        eyebrow="Delegated workspace"
        title="Security posture"
        description="Select one Group and policy to view its authorized inventory."
      >
        <AppButton onClick={() => onNavigate('policies')}>Browse policies</AppButton>
      </AppPage>
    );
  }
  const providersReporting = overview.providers.filter((provider) => provider.sync_complete).length;
  const providerAlerts = overview.providers.flatMap((provider) => {
    if (provider.sync_status === 'FAILED') {
      return [
        {
          provider: provider.display_name,
          message: `Synchronization failed${provider.error_code ? ` (${provider.error_code})` : ''}.`,
        },
      ];
    }
    if (
      provider.sync_status === 'INCOMPLETE' ||
      (provider.sync_status === 'COMPLETED' && !provider.sync_complete)
    ) {
      return [
        {
          provider: provider.display_name,
          message: 'Synchronization completed without a complete inventory.',
        },
      ];
    }
    if (provider.sync_status === 'RUNNING') {
      return [
        { provider: provider.display_name, message: 'Synchronization is currently in progress.' },
      ];
    }
    return [];
  });
  return (
    <AppPage
      eyebrow="Operational overview"
      title="Security posture"
      description="Current provider inventory and delegated firewall-management activity across your accessible control plane."
    >
      <AppSimpleGrid cols={{ base: 1, xs: 2, lg: 4 }}>
        <MetricCard
          label="Synchronized providers"
          value={overview.counts.managers}
          detail={`${providersReporting} with complete inventory`}
          icon={<IconPlugConnected size={19} />}
        />
        <MetricCard
          label="Accessible policies"
          value={overview.counts.policies}
          detail="Across synchronized managers"
          icon={<IconShieldCheck size={19} />}
        />
        <MetricCard
          label="Firewall objects"
          value={overview.counts.objects}
          detail="Normalized inventory"
          icon={<IconPackages size={19} />}
        />
        <MetricCard
          label="Open Changesets"
          value={overview.counts.change_sets}
          detail="Ready, queued, or executing"
          icon={<IconFileDiff size={19} />}
        />
      </AppSimpleGrid>
      <AppSimpleGrid cols={{ base: 1, lg: 3 }}>
        <AppCard style={{ gridColumn: 'span 2' }}>
          <AppSection
            title="Provider estate"
            description="Real providers and synchronized inventory"
          >
            {overview.providers.length === 0 ? (
              <AppEmptyState
                title="No synchronized providers"
                description="Provider inventory is not currently available."
              />
            ) : (
              <AppSimpleGrid cols={{ base: 1, sm: 2 }}>
                {overview.providers.map((provider) => (
                  <AppCard key={provider.provider} className="fm-subtle-panel">
                    <AppGroup justify="space-between" align="start">
                      <AppGroup gap="xs">
                        <AppProviderBadge provider={provider.provider} />
                        <AppText fw={650}>{provider.display_name}</AppText>
                      </AppGroup>
                      <AppStatusBadge value={provider.writable ? 'ACTIVE' : 'READ_ONLY'} />
                    </AppGroup>
                    <AppText size="xs" c="dimmed" mt={6}>
                      Version {provider.provider_version}
                    </AppText>
                    <AppSimpleGrid cols={{ base: 3 }} mt="lg">
                      <div>
                        <AppText size="xl" fw={700}>
                          {provider.policy_count}
                        </AppText>
                        <AppText size="xs" c="dimmed">
                          Policies
                        </AppText>
                      </div>
                      <div>
                        <AppText size="xl" fw={700}>
                          {provider.rule_count}
                        </AppText>
                        <AppText size="xs" c="dimmed">
                          Rules
                        </AppText>
                      </div>
                      <div>
                        <AppText size="xl" fw={700}>
                          {provider.object_count}
                        </AppText>
                        <AppText size="xs" c="dimmed">
                          Objects
                        </AppText>
                      </div>
                    </AppSimpleGrid>
                  </AppCard>
                ))}
              </AppSimpleGrid>
            )}
          </AppSection>
        </AppCard>
        <AppCard>
          <AppSection title="Needs attention" description="Conditions that may affect operations">
            {overview.providers.length > 0 && providerAlerts.length === 0 ? (
              <AppEmptyState
                title="No active alerts"
                description="All reporting providers have synchronized policy inventory."
              />
            ) : overview.providers.length === 0 ? (
              <AppGroup align="start" wrap="nowrap">
                <IconAlertTriangle color="var(--fm-warning)" size={20} />
                <div>
                  <AppText fw={650}>No provider inventory</AppText>
                  <AppText size="xs" c="dimmed">
                    No reporting providers are available to synchronize.
                  </AppText>
                </div>
              </AppGroup>
            ) : (
              <AppStack gap="sm">
                {providerAlerts.map((alert) => (
                  <AppGroup key={`${alert.provider}-${alert.message}`} align="start" wrap="nowrap">
                    <IconAlertTriangle color="var(--fm-warning)" size={20} />
                    <div>
                      <AppText fw={650}>{alert.provider}</AppText>
                      <AppText size="xs" c="dimmed">
                        {alert.message}
                      </AppText>
                    </div>
                  </AppGroup>
                ))}
              </AppStack>
            )}
          </AppSection>
        </AppCard>
      </AppSimpleGrid>
      <AppCard>
        <AppSection title="Start working" description="Choose an operational workspace">
          <AppSimpleGrid cols={{ base: 1, sm: 3 }}>
            <QuickLink
              title="Policies"
              description="Choose an accessible policy and inspect its delegated boundary."
              onClick={() => onNavigate('policies')}
            />
            <QuickLink
              title="Rules"
              description="Review Group-owned rules and create controlled policy changes."
              onClick={() => onNavigate('rules')}
            />
            <QuickLink
              title="Objects"
              description="Inspect ownership, use rights, and provider support."
              onClick={() => onNavigate('objects')}
            />
          </AppSimpleGrid>
        </AppSection>
      </AppCard>
    </AppPage>
  );
}

function QuickLink({
  title,
  description,
  onClick,
}: {
  title: string;
  description: string;
  onClick: () => void;
}) {
  return (
    <button
      className="fm-nav-item fm-subtle-panel"
      style={{ minHeight: 84, alignItems: 'flex-start', padding: 14 }}
      onClick={onClick}
    >
      <div>
        <AppText fw={650}>{title}</AppText>
        <AppText size="xs" c="dimmed" mt={4}>
          {description}
        </AppText>
      </div>
    </button>
  );
}
