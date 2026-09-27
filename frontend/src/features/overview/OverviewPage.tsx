import { lazy, Suspense, useCallback, useEffect, useState } from 'react';
import {
  IconAlertTriangle,
  IconFileDiff,
  IconPackages,
  IconPlugConnected,
  IconShieldCheck,
} from '@tabler/icons-react';

import { loadDelegatedPolicies, type Overview, type Session } from '../../api/client';
import { DevelopmentUserSelector } from '../auth/DevelopmentUserSelector';
import { DelegatedWorkspace } from '../delegated/DelegatedWorkspace';
import { AuditPage, SyncDriftPage } from '../operations/OperationsPages';
import { ProviderConnectionsPanel } from '../provider-connections/ProviderConnectionsPanel';
import { AdminChangeSetsPanel } from '../changesets/AdminChangeSetsPanel';
import {
  AppCard,
  AppEmptyState,
  AppErrorState,
  AppGroup,
  AppIdentityNotice,
  AppLayout,
  AppLoadingState,
  AppPage,
  AppProviderBadge,
  AppSection,
  AppSimpleGrid,
  AppStatusBadge,
  AppText,
  MetricCard,
  type AppRoute,
} from '../../ui';
import { useOverview } from './useOverview';

const AdministrationPanel = lazy(() =>
  import('../admin/AdministrationPanel').then((module) => ({
    default: module.AdministrationPanel,
  })),
);

export function OverviewPage() {
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
  return <ReadyApplication overview={state.overview} session={state.session} />;
}

function StandaloneState({ children }: { children: React.ReactNode }) {
  return <div style={{ maxWidth: 720, margin: '15vh auto', padding: 24 }}>{children}</div>;
}

function ReadyApplication({ overview, session }: { overview: Overview; session: Session }) {
  const [route, setRoute] = useState<AppRoute>('home');
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
      route={route}
      onRouteChange={setRoute}
      headerActions={<DevelopmentUserSelector compact />}
    >
      {route === 'home' && (
        <Dashboard overview={overview} session={session} onNavigate={setRoute} />
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
          onNavigate={(view) => setRoute(view)}
        />
      )}
      {route === 'providers' && admin && (
        <AppPage
          eyebrow="Infrastructure"
          title="Provider connections"
          description="Read-only FMC and Security Cloud Control integrations, connection health, and credential lifecycle."
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
      {route === 'changesets-admin' && admin && (
        <AppPage
          eyebrow="Operations"
          title="All ChangeSets"
          description="Organization-wide ChangeSet status and cleanup for administrators."
        >
          <AdminChangeSetsPanel />
        </AppPage>
      )}
      {route === 'sync' && admin && <SyncDriftPage activeGroupId={workingContext.groupId} />}
      {route === 'audit' && admin && <AuditPage />}
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
  overview,
  session,
  onNavigate,
}: {
  overview: Overview;
  session: Session;
  onNavigate: (route: AppRoute) => void;
}) {
  const providersHealthy = overview.providers.filter(
    (provider) => provider.policy_count > 0,
  ).length;
  return (
    <AppPage
      eyebrow="Operational overview"
      title="Security posture"
      description="Current provider inventory and delegated firewall-management activity across your accessible control plane."
    >
      <AppIdentityNotice email={session.email} role={session.role} />
      <AppSimpleGrid cols={{ base: 1, xs: 2, lg: 4 }}>
        <MetricCard
          label="Synchronized providers"
          value={overview.counts.managers}
          detail={`${providersHealthy} with reporting inventory`}
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
          label="Open ChangeSets"
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
            {overview.providers.length > 0 && providersHealthy === overview.providers.length ? (
              <AppEmptyState
                title="No active alerts"
                description="All reporting providers have synchronized policy inventory."
              />
            ) : (
              <AppGroup align="start" wrap="nowrap">
                <IconAlertTriangle color="var(--fm-warning)" size={20} />
                <div>
                  <AppText fw={650}>
                    {overview.providers.length === 0
                      ? 'No provider inventory'
                      : 'Inventory unavailable'}
                  </AppText>
                  <AppText size="xs" c="dimmed">
                    {overview.providers.length === 0
                      ? 'No real provider inventory is available to report.'
                      : 'One or more providers have no synchronized policies.'}
                  </AppText>
                </div>
              </AppGroup>
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
              description="Review Group-owned rules and create safe mock-provider changes."
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
