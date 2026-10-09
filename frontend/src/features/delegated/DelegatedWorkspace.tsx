// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  IconArrowRight,
  IconArrowsMoveVertical,
  IconAlertTriangle,
  IconCategory,
  IconChevronDown,
  IconChevronRight,
  IconCloudDownload,
  IconCircleCheck,
  IconEdit,
  IconFileDescription,
  IconFileTextShield,
  IconHierarchy3,
  IconPackages,
  IconPlus,
  IconSearch,
  IconShieldCheck,
  IconShieldX,
  IconStar,
  IconTrash,
  IconUsersGroup,
} from '@tabler/icons-react';

import {
  addDraftCategory,
  addDraftObject,
  addDraftRule,
  ApiError,
  acceptProviderState,
  changeSetAction,
  createChangeSet,
  loadDelegatedContext,
  loadChangeSets,
  loadDelegatedPolicies,
  setDefaultDelegatedContext,
  type ActiveGroup,
  type ChangeSet,
  type DelegatedContext,
  type DelegatedPolicy,
} from '../../api/client';
import {
  AppActionButton as ActionButton,
  AppAlert as Alert,
  AppButton as Button,
  AppCard,
  AppCheckbox as Checkbox,
  AppDataTable,
  AppDialog as Dialog,
  AppEmptyState,
  AppErrorState,
  AppGroup as Group,
  AppLoadingState,
  AppMultiSelect as MultiSelect,
  AppPage,
  AppSelect as Select,
  AppSimpleGrid as SimpleGrid,
  AppStack as Stack,
  AppStatusBadge,
  AppTooltip,
  AppTable as Table,
  AppText as Text,
  AppTextInput as TextInput,
  AppTitle as Title,
  MetricCard,
} from '../../ui';
import { ChangeSetPanel } from '../changesets/ChangeSetPanel';
import { AdaptivePagination, useAdaptivePageSize } from '../shared/AdaptivePagination';
import { useDelegatedWorkspace } from './useDelegatedWorkspace';

type WorkspaceView = 'policies' | 'rules' | 'objects' | 'changes';

export function DelegatedWorkspace({
  groups,
  initialView = 'rules',
  initialGroupId,
  initialPolicyId,
  defaultGroupId,
  defaultPolicyId,
  onContextChange,
  onDefaultChange,
}: {
  groups: ActiveGroup[];
  initialView?: WorkspaceView;
  initialGroupId?: string;
  initialPolicyId?: string;
  defaultGroupId?: string;
  defaultPolicyId?: string;
  onContextChange?: (groupId?: string, policyId?: string, group?: string, policy?: string) => void;
  onDefaultChange?: (groupId: string, policyId: string) => void;
}) {
  const view = initialView;
  const workspace = useDelegatedWorkspace(
    groups,
    initialGroupId,
    initialPolicyId,
    view === 'rules',
    view === 'rules',
    view,
  );
  const [activity, setActivity] = useState<ChangeSet[]>([]);
  const activeGroup = groups.find((group) => group.id === workspace.activeGroupId);
  const activePolicy =
    workspace.state.status === 'ready'
      ? workspace.state.context.policy
      : 'policies' in workspace.state
        ? workspace.state.policies.find((policy) => policy.id === workspace.activePolicyId)
        : undefined;
  useEffect(() => {
    onContextChange?.(
      workspace.activeGroupId || undefined,
      workspace.activePolicyId || undefined,
      activeGroup?.name,
      activePolicy?.name,
    );
  }, [
    activeGroup?.name,
    activePolicy?.name,
    onContextChange,
    workspace.activeGroupId,
    workspace.activePolicyId,
  ]);
  useEffect(() => {
    if (
      !workspace.activeGroupId ||
      !workspace.activePolicyId ||
      view === 'policies' ||
      view === 'changes'
    ) {
      return;
    }
    let current = true;
    let refreshing = false;
    const refresh = () => {
      if (refreshing) return;
      refreshing = true;
      void loadChangeSets(workspace.activeGroupId)
        .then((items) => {
          if (current) setActivity(items);
        })
        .catch(() => {
          // Inventory refresh remains useful even if activity polling briefly fails.
        })
        .finally(() => {
          refreshing = false;
        });
    };
    refresh();
    const timer = window.setInterval(refresh, 10_000);
    return () => {
      current = false;
      window.clearInterval(timer);
    };
  }, [view, workspace.activeGroupId, workspace.activePolicyId]);
  return (
    <AppPage
      eyebrow="Firewall management"
      title={
        view === 'rules'
          ? 'Rules workspace'
          : view === 'objects'
            ? 'Object inventory'
            : view === 'changes'
              ? 'Changesets'
              : 'Policy browser'
      }
      description={
        view === 'policies'
          ? 'Choose the Group and Access Policy context used throughout the firewall workspace.'
          : view === 'rules'
            ? 'Build and maintain the ordered rules owned by the active Group.'
            : view === 'objects'
              ? 'Create and manage the firewall objects authorized for the active Group.'
              : 'Track submitted provider changes, execution results, and reconciliation.'
      }
    >
      {view !== 'policies' && workspace.state.status === 'unavailable' && (
        <Alert color="yellow" title="Delegated access unavailable">
          {workspace.state.reason}
        </Alert>
      )}
      {view !== 'policies' && workspace.state.status === 'loading' && (
        <AppLoadingState label="Recalculating Group and policy access" />
      )}
      {view !== 'policies' && workspace.state.status === 'error' && (
        <AppErrorState
          message={workspace.state.message}
          reference={workspace.state.correlationId}
        />
      )}
      {view === 'policies' && (
        <PolicyMappings
          groups={groups}
          activeGroupId={workspace.activeGroupId}
          activePolicyId={workspace.activePolicyId}
          defaultGroupId={defaultGroupId}
          defaultPolicyId={defaultPolicyId}
          onActivate={workspace.activateMapping}
          onDefaultChange={onDefaultChange}
        />
      )}
      {workspace.state.status === 'ready' && view === 'rules' && (
        <>
          <WorkspaceMetrics view="rules" context={workspace.state.context} />
          <RulesWorkspace
            key={`${workspace.state.activePolicyId}:${workspace.state.context.rules.map((rule) => `${rule.id}:${rule.revision}:${rule.position}`).join('|')}`}
            context={workspace.state.context}
            groupName={activeGroup?.name ?? 'Current Group'}
            groupSlug={activeGroup?.provider_slug ?? 'GROUP'}
            activeGroupId={workspace.state.activeGroupId}
            activity={activity}
            onContextRefresh={workspace.refreshContext}
          />
        </>
      )}
      {workspace.state.status === 'ready' && view === 'objects' && (
        <>
          <WorkspaceMetrics
            view="objects"
            context={workspace.state.context}
            activeGroupId={workspace.state.activeGroupId}
          />
          <ObjectsWorkspace
            context={workspace.state.context}
            groupName={activeGroup?.name ?? 'Current Group'}
            groupSlug={activeGroup?.provider_slug ?? 'GROUP'}
            activeGroupId={workspace.state.activeGroupId}
            activity={activity}
          />
        </>
      )}
      {workspace.state.status === 'ready' && view === 'changes' && (
        <ChangeSetPanel
          key={`${workspace.state.activeGroupId}-${workspace.state.activePolicyId}`}
          activeGroupId={workspace.state.activeGroupId}
          context={workspace.state.context}
        />
      )}
    </AppPage>
  );
}

function WorkspaceMetrics({
  view,
  context,
  activeGroupId,
}: {
  view: 'rules' | 'objects';
  context: DelegatedContext;
  activeGroupId?: string;
}) {
  if (view === 'rules') {
    const allows = context.rules.filter((rule) => rule.action.toUpperCase() === 'ALLOW').length;
    const restrictive = context.rules.filter(
      (rule) => rule.action.toUpperCase() === 'BLOCK',
    ).length;
    const securityControls = context.rules.filter(
      (rule) => Boolean(rule.intrusion_policy_id) || Boolean(rule.file_policy_id),
    ).length;
    return (
      <SimpleGrid cols={{ base: 1, xs: 2, lg: 4 }}>
        <MetricCard
          label="Managed rules"
          value={context.rules.length}
          detail="Owned by this Group"
          icon={<IconHierarchy3 size={19} />}
        />
        <MetricCard
          label="Allow rules"
          value={allows}
          detail="Permitted traffic paths"
          icon={<IconShieldCheck size={19} />}
        />
        <MetricCard
          label="Restrictive rules"
          value={restrictive}
          detail="Blocked traffic paths"
          icon={<IconShieldX size={19} />}
        />
        <MetricCard
          label="Inspection rules"
          value={securityControls}
          detail="IPS or file policy enabled"
          icon={<IconShieldCheck size={19} />}
        />
      </SimpleGrid>
    );
  }
  const owned = context.objects.filter((object) => object.owner_group_id === activeGroupId).length;
  const objectTypes = new Set(context.objects.map((object) => object.object_type)).size;
  return (
    <SimpleGrid cols={{ base: 1, xs: 2, lg: 4 }}>
      <MetricCard
        label="Accessible objects"
        value={context.objects.length}
        detail="Available to this Group in this policy"
        icon={<IconPackages size={19} />}
      />
      <MetricCard
        label="Group-owned objects"
        value={owned}
        detail="Owned by this Group; manageable if permitted"
        icon={<IconUsersGroup size={19} />}
      />
      <MetricCard
        label="Shared objects"
        value={context.objects.length - owned}
        detail="Provider or other Group; available for rule use"
        icon={<IconShieldCheck size={19} />}
      />
      <MetricCard
        label="Object types"
        value={objectTypes}
        detail="Distinct categories in this context"
        icon={<IconCategory size={19} />}
      />
    </SimpleGrid>
  );
}

type PolicyMapping = {
  group: ActiveGroup;
  policy: DelegatedPolicy;
  capabilities: string[];
  objectCreate: string[];
  ipRanges: string[];
  authorizationLoaded: boolean;
};

function PolicyMappings({
  groups,
  activeGroupId,
  activePolicyId,
  defaultGroupId,
  defaultPolicyId,
  onActivate,
  onDefaultChange,
}: {
  groups: ActiveGroup[];
  activeGroupId: string;
  activePolicyId: string;
  defaultGroupId?: string;
  defaultPolicyId?: string;
  onActivate: (groupId: string, policyId: string) => void;
  onDefaultChange?: (groupId: string, policyId: string) => void;
}) {
  const [mappings, setMappings] = useState<PolicyMapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [savingDefault, setSavingDefault] = useState('');
  const [accessMapping, setAccessMapping] = useState<PolicyMapping | null>(null);

  useEffect(() => {
    let current = true;
    void Promise.all(
      groups.map(async (group) => {
        const policies = await loadDelegatedPolicies(group.id);
        return policies.map((policy) => ({
          group,
          policy,
          capabilities: [],
          objectCreate: [],
          ipRanges: [],
          authorizationLoaded: false,
        }));
      }),
    )
      .then(async (results) => {
        const baseMappings = results.flat();
        if (!current) return;
        setMappings(baseMappings);
        setLoading(false);
        const details = await Promise.allSettled(
          baseMappings.map(async (mapping) => ({
            key: `${mapping.group.id}:${mapping.policy.id}`,
            context: await loadDelegatedContext(mapping.group.id, mapping.policy.id),
          })),
        );
        if (!current) return;
        const loaded = new Map(
          details.flatMap((result) =>
            result.status === 'fulfilled'
              ? [[result.value.key, result.value.context] as const]
              : [],
          ),
        );
        setMappings((rows) =>
          rows.map((mapping) => {
            const context = loaded.get(`${mapping.group.id}:${mapping.policy.id}`);
            return context
              ? {
                  ...mapping,
                  capabilities: context.capabilities ?? [],
                  objectCreate: (context.object_create ?? []).map((item) => item.object_type),
                  ipRanges: context.ip_ranges ?? [],
                  authorizationLoaded: true,
                }
              : { ...mapping, authorizationLoaded: true };
          }),
        );
      })
      .catch((caught: unknown) => {
        if (current) {
          setError(
            caught instanceof Error ? caught.message : 'Policy mappings could not be loaded.',
          );
          setLoading(false);
        }
      });
    return () => {
      current = false;
    };
  }, [groups]);

  const makeDefault = async (mapping: PolicyMapping) => {
    const key = `${mapping.group.id}:${mapping.policy.id}`;
    setSavingDefault(key);
    setError('');
    try {
      await setDefaultDelegatedContext(mapping.group.id, mapping.policy.id);
      onDefaultChange?.(mapping.group.id, mapping.policy.id);
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : 'The default mapping could not be saved.',
      );
    } finally {
      setSavingDefault('');
    }
  };

  if (loading) return <AppLoadingState label="Loading Group and policy mappings" />;
  const mappedGroups = new Set(mappings.map((mapping) => mapping.group.id)).size;
  const mappedPolicies = new Set(mappings.map((mapping) => mapping.policy.id)).size;
  const hasDefault = Boolean(defaultGroupId && defaultPolicyId);
  return (
    <Stack gap="lg">
      <SimpleGrid cols={{ base: 1, xs: 2, lg: 4 }}>
        <MetricCard
          label="Policy mappings"
          value={mappings.length}
          detail="Authorized working contexts"
          icon={<IconHierarchy3 size={19} />}
        />
        <MetricCard
          label="Accessible Groups"
          value={mappedGroups}
          detail="Available identities"
          icon={<IconUsersGroup size={19} />}
        />
        <MetricCard
          label="Access Policies"
          value={mappedPolicies}
          detail="Unique delegated policies"
          icon={<IconShieldCheck size={19} />}
        />
        <MetricCard
          label="Login default"
          value={hasDefault ? 'Configured' : 'Not set'}
          detail={hasDefault ? 'Automatically selected at login' : 'Choose a default below'}
          icon={<IconStar size={19} />}
        />
      </SimpleGrid>
      <AppCard component="section" aria-labelledby="policy-mappings-heading">
        <Group justify="space-between" align="start" mb="md">
          <div>
            <Title id="policy-mappings-heading" order={3} size="h4">
              Group and Access Policy mappings
            </Title>
            <Text c="dimmed" size="sm">
              Choose the working context to activate now, or the default to activate at login.
            </Text>
          </div>
          <AppStatusBadge value="COUNT" label={`${mappings.length} mappings`} />
        </Group>
        {error && (
          <Alert color="red" title="Mapping update failed" mb="md">
            {error}
          </Alert>
        )}
        {mappings.length === 0 ? (
          <AppEmptyState
            title="No policy mappings"
            description="No Access Policy is delegated to your active Groups."
          />
        ) : (
          <div className="fm-directory-table fm-policy-mapping-table">
            <AppDataTable label="Group and Access Policy mappings">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Group</Table.Th>
                  <Table.Th>Access Policy</Table.Th>
                  <Table.Th>Assigned access</Table.Th>
                  <Table.Th>Working context</Table.Th>
                  <Table.Th>Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {mappings.map((mapping) => {
                  const active =
                    mapping.group.id === activeGroupId && mapping.policy.id === activePolicyId;
                  const isDefault =
                    mapping.group.id === defaultGroupId && mapping.policy.id === defaultPolicyId;
                  const key = `${mapping.group.id}:${mapping.policy.id}`;
                  return (
                    <Table.Tr
                      key={key}
                      className={active ? 'fm-policy-mapping-selected' : undefined}
                    >
                      <Table.Td>{mapping.group.name}</Table.Td>
                      <Table.Td>
                        <Group gap="xs" wrap="nowrap">
                          <span>{mapping.policy.name}</span>
                          {isDefault && (
                            <AppStatusBadge value="ASSIGNED" label="Default" size="xs" />
                          )}
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <ActionButton
                          intent="quiet"
                          disabled={!mapping.authorizationLoaded}
                          onClick={() => setAccessMapping(mapping)}
                        >
                          {mapping.authorizationLoaded ? 'View access' : 'Loading…'}
                        </ActionButton>
                      </Table.Td>
                      <Table.Td>
                        {active && <AppStatusBadge value="ACTIVE" label="Selected" size="xs" />}
                      </Table.Td>
                      <Table.Td>
                        <Group gap="xs" wrap="nowrap" justify="flex-end">
                          {!active && (
                            <ActionButton
                              intent="success"
                              onClick={() => onActivate(mapping.group.id, mapping.policy.id)}
                            >
                              Select
                            </ActionButton>
                          )}
                          {!isDefault && (
                            <ActionButton
                              intent="quiet"
                              loading={savingDefault === key}
                              onClick={() => void makeDefault(mapping)}
                            >
                              Set default
                            </ActionButton>
                          )}
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </AppDataTable>
          </div>
        )}
        <AccessDetailsDialog mapping={accessMapping} onClose={() => setAccessMapping(null)} />
      </AppCard>
    </Stack>
  );
}

function AccessDetailsDialog({
  mapping,
  onClose,
}: {
  mapping: PolicyMapping | null;
  onClose: () => void;
}) {
  return (
    <>
      <Dialog
        opened={mapping !== null}
        onClose={onClose}
        title={mapping ? `${mapping.group.name} · ${mapping.policy.name}` : 'Assigned access'}
        centered
        size="lg"
      >
        {mapping && (
          <Stack gap="lg">
            <Text size="sm" c="dimmed">
              Permissions available when this Group works in this Access Policy.
            </Text>
            <div className="fm-access-detail-grid">
              {capabilityGroups(mapping.capabilities, mapping.objectCreate).map((group) => (
                <section className="fm-access-detail-section" key={group.label}>
                  <Text
                    className="fm-access-detail-label"
                    size="xs"
                    fw={800}
                    tt="uppercase"
                    lts=".1em"
                  >
                    {group.label}
                  </Text>
                  <div className="fm-policy-rights-chips">
                    {group.values.map((value) => (
                      <span
                        className={`fm-policy-right-chip${value.startsWith('create_object:') ? ' fm-policy-right-chip-create' : ''}`}
                        key={value}
                      >
                        {formatCapability(value)}
                      </span>
                    ))}
                  </div>
                </section>
              ))}
              <section className="fm-access-detail-section">
                <Text
                  className="fm-access-detail-label"
                  size="xs"
                  fw={800}
                  tt="uppercase"
                  lts=".1em"
                >
                  IP ranges
                </Text>
                <Text size="sm" c="dimmed" className="fm-code">
                  {mapping.ipRanges.length > 0 ? mapping.ipRanges.join(' · ') : 'None assigned'}
                </Text>
              </section>
            </div>
          </Stack>
        )}
      </Dialog>
    </>
  );
}

function RulesWorkspace({
  context,
  groupName,
  groupSlug,
  activeGroupId,
  activity,
  onContextRefresh,
}: {
  context: DelegatedContext;
  groupName: string;
  groupSlug: string;
  activeGroupId: string;
  activity: ChangeSet[];
  onContextRefresh: () => Promise<void>;
}) {
  const [query, setQuery] = useState('');
  const [creating, setCreating] = useState(false);
  const [correctionRules, setCorrectionRules] = useState<PendingRule[]>([]);
  const [editing, setEditing] = useState<DelegatedContext['rules'][number]>();
  const [editingCorrectionOperation, setEditingCorrectionOperation] =
    useState<ChangeSet['operations'][number]>();
  const [deleting, setDeleting] = useState<DelegatedContext['rules'][number]>();
  const [deletePendingIds, setDeletePendingIds] = useState<string[]>([]);
  const [deleteNotice, setDeleteNotice] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [acceptingDriftId, setAcceptingDriftId] = useState('');
  const [acceptError, setAcceptError] = useState('');
  const acceptRuleProviderState = async (driftId: string) => {
    setAcceptingDriftId(driftId);
    setAcceptError('');
    try {
      await acceptProviderState(driftId, activeGroupId);
      await onContextRefresh();
    } catch (reason) {
      setAcceptError(
        reason instanceof ApiError ? reason.message : 'Provider state could not be accepted.',
      );
    } finally {
      setAcceptingDriftId('');
    }
  };
  const recentCutoff = useRecentActivityCutoff();
  const trackedRuleOperations = activity
    .filter(
      (changeSet) =>
        changeSet.access_policy_id === context.policy.id &&
        (['READY', 'QUEUED', 'EXECUTING'].includes(changeSet.state) ||
          (['SUCCEEDED', 'FAILED', 'CONFLICT', 'PARTIALLY_SUCCEEDED'].includes(changeSet.state) &&
            Date.parse(changeSet.updated_at) >= recentCutoff)),
    )
    .flatMap((changeSet) =>
      changeSet.operations
        .filter((operation) =>
          ['CREATE_RULE', 'MODIFY_RULE', 'DELETE_RULE'].includes(operation.kind),
        )
        .map((operation) => ({ changeSet, operation })),
    );
  const activeRuleOperations = trackedRuleOperations.filter(({ changeSet }) =>
    ['QUEUED', 'EXECUTING'].includes(changeSet.state),
  );
  const pendingDeleteRuleIds = new Set(
    activity
      .filter(
        (changeSet) =>
          changeSet.access_policy_id === context.policy.id &&
          !['SUCCEEDED', 'CANCELLED', 'REJECTED', 'ROLLED_BACK'].includes(changeSet.state),
      )
      .flatMap((changeSet) =>
        changeSet.operations
          .filter((operation) => operation.kind === 'DELETE_RULE')
          .map((operation) => String(operation.payload.rule_id ?? '')),
      ),
  );
  const pendingRuleOperations = activity
    .filter(
      (changeSet) =>
        changeSet.access_policy_id === context.policy.id &&
        changeSet.approval_required &&
        changeSet.state === 'READY',
    )
    .flatMap((changeSet) =>
      changeSet.operations
        .filter((operation) => operation.kind === 'CREATE_RULE' || operation.kind === 'MODIFY_RULE')
        .map((operation) => ({ changeSet, operation })),
    )
    .filter(({ operation }) =>
      String(operation.payload.name ?? '')
        .toLowerCase()
        .includes(query.toLowerCase()),
    );
  const rejectedRuleCandidates = activity
    .filter(
      (changeSet) =>
        changeSet.access_policy_id === context.policy.id && changeSet.state === 'REJECTED',
    )
    .flatMap((changeSet) =>
      changeSet.operations
        .filter((operation) => operation.kind === 'CREATE_RULE' || operation.kind === 'MODIFY_RULE')
        .map((operation) => ({ changeSet, operation })),
    );
  const latestRejectedRules = new Map<string, (typeof rejectedRuleCandidates)[number]>();
  for (const candidate of rejectedRuleCandidates) {
    const key = String(candidate.operation.payload.name ?? '').toLowerCase();
    const existing = latestRejectedRules.get(key);
    if (
      !existing ||
      Date.parse(candidate.changeSet.rejected_at ?? candidate.changeSet.updated_at) >=
        Date.parse(existing.changeSet.rejected_at ?? existing.changeSet.updated_at)
    ) {
      latestRejectedRules.set(key, candidate);
    }
  }
  const replacementRuleKeys = new Set(
    activity
      .filter(
        (changeSet) =>
          changeSet.access_policy_id === context.policy.id && changeSet.state !== 'REJECTED',
      )
      .flatMap((changeSet) =>
        changeSet.operations
          .filter(
            (operation) => operation.kind === 'CREATE_RULE' || operation.kind === 'MODIFY_RULE',
          )
          .map((operation) => String(operation.payload.name ?? '').toLowerCase()),
      ),
  );
  const rejectedRuleOperations = [...latestRejectedRules.values()].filter(({ operation }) => {
    const key = String(operation.payload.name ?? '').toLowerCase();
    return !replacementRuleKeys.has(key) && key.includes(query.toLowerCase());
  });
  const providerOrder = useMemo(
    () => [...context.rules].sort((left, right) => left.position - right.position),
    [context.rules],
  );
  const [orderedRuleIds, setOrderedRuleIds] = useState<string[]>(() =>
    providerOrder.map((rule) => rule.id),
  );
  const [draggedRuleId, setDraggedRuleId] = useState('');
  const [orderBusy, setOrderBusy] = useState(false);
  const [orderError, setOrderError] = useState('');
  const [orderQueued, setOrderQueued] = useState<ChangeSet>();
  const orderedRules = orderedRuleIds
    .map((id) => context.rules.find((rule) => rule.id === id))
    .filter((rule): rule is DelegatedContext['rules'][number] => Boolean(rule));
  const filtered = useMemo(
    () => orderedRules.filter((rule) => rule.name.toLowerCase().includes(query.toLowerCase())),
    [orderedRules, query],
  );
  const orderChanged =
    orderedRuleIds.length === providerOrder.length &&
    orderedRuleIds.some((id, index) => id !== providerOrder[index]?.id);
  const reorderEnabled =
    context.provider_writable && context.capabilities.includes('reorder_rule') && !query;
  const moveDraggedRule = (targetRuleId: string, after: boolean) => {
    if (!draggedRuleId || draggedRuleId === targetRuleId || !reorderEnabled) return;
    setOrderedRuleIds((current) => {
      const next = current.filter((id) => id !== draggedRuleId);
      const targetIndex = next.indexOf(targetRuleId);
      next.splice(targetIndex + (after ? 1 : 0), 0, draggedRuleId);
      return next;
    });
    setOrderError('');
  };
  const saveOrder = async () => {
    if (!orderChanged) return;
    setOrderBusy(true);
    setOrderError('');
    setOrderQueued(undefined);
    try {
      const simulatedOrder = providerOrder.map((rule) => rule.id);
      const rulesToMove: DelegatedContext['rules'] = [];
      orderedRules.forEach((rule, desiredIndex) => {
        const currentIndex = simulatedOrder.indexOf(rule.id);
        if (currentIndex === desiredIndex) return;
        rulesToMove.push(rule);
        simulatedOrder.splice(currentIndex, 1);
        simulatedOrder.splice(desiredIndex, 0, rule.id);
      });
      if (rulesToMove.some((rule) => !rule.category_id)) {
        setOrderError('Rule ordering is unavailable until the Group rule section is synchronized.');
        return;
      }
      const title = `${groupName} rule order · ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`;
      const draft = await createChangeSet(
        activeGroupId,
        context.policy.id,
        title,
        `Apply the saved ${groupName} rule order from the Rules workspace.`,
      );
      let withMoves = draft;
      for (const rule of rulesToMove) {
        const desiredIndex = orderedRules.findIndex((item) => item.id === rule.id);
        const target = providerOrder[desiredIndex];
        if (!target) {
          setOrderError('The provider rule order changed. Refresh and arrange the rules again.');
          return;
        }
        withMoves = await addDraftRule(
          withMoves.id,
          activeGroupId,
          {
            rule_id: rule.id,
            category_id: rule.category_id,
            position: target.position,
          },
          'MOVE_RULE',
        );
      }
      const validated = await changeSetAction(withMoves.id, activeGroupId, 'preflight');
      if (validated.state !== 'READY') {
        setOrderError(rulePreflightError(validated));
        return;
      }
      setOrderQueued(await changeSetAction(validated.id, activeGroupId, 'execute'));
    } catch (reason) {
      setOrderError(ruleDialogError(reason));
    } finally {
      setOrderBusy(false);
    }
  };
  const queueRuleDeletion = async (rule: DelegatedContext['rules'][number]) => {
    setDeletePendingIds((current) => [...new Set([...current, rule.id])]);
    setDeleteError('');
    setDeleteNotice(`Preparing deletion for ${rule.name}…`);
    try {
      const draft = await createChangeSet(
        activeGroupId,
        context.policy.id,
        `${groupName} rule deletion · ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`,
        `Delete ${rule.name} from the Rules workspace.`,
      );
      const withRule = await addDraftRule(
        draft.id,
        activeGroupId,
        { rule_id: rule.id },
        'DELETE_RULE',
      );
      const validated = await changeSetAction(withRule.id, activeGroupId, 'preflight');
      if (validated.state !== 'READY') {
        setDeleteError(`${rule.name}: ${rulePreflightError(validated)}`);
        return;
      }
      await changeSetAction(validated.id, activeGroupId, 'execute');
      setDeleteNotice(
        `Deletion for ${rule.name} is queued. You can continue working while it runs.`,
      );
    } catch (reason) {
      setDeleteError(`${rule.name}: ${ruleDialogError(reason)}`);
    } finally {
      setDeletePendingIds((current) => current.filter((id) => id !== rule.id));
    }
  };
  return (
    <AppCard>
      <Group justify="space-between" align="end" mb="md">
        <div>
          <Text className="fm-eyebrow">Delegated category</Text>
          <Title order={2} size="h4">
            {groupName} rules
          </Title>
          <Text size="xs" c="dimmed">
            Rules remain owned by the active Group and scoped to the selected policy.
          </Text>
        </div>
        <Button
          leftSection={<IconPlus size={16} />}
          disabled={!context.provider_writable || !context.capabilities.includes('create_rule')}
          onClick={() => setCreating(true)}
        >
          Create rule
        </Button>
      </Group>
      {context.policy_device_assignment === 'UNASSIGNED' && (
        <Alert color="yellow" title="Policy is not assigned to a firewall" mb="md">
          These rules are synchronized to {context.provider_name}, but the selected policy is not
          currently assigned to a firewall device and therefore is not deployed to a device. This
          notice will clear automatically when the policy assignment changes.
        </Alert>
      )}
      <CreateRuleDialog
        key={`create-${correctionRules.map((rule) => rule.id).join('|') || 'new'}`}
        opened={creating}
        onClose={() => {
          setCreating(false);
          setCorrectionRules([]);
        }}
        activeGroupId={activeGroupId}
        groupName={groupName}
        groupSlug={groupSlug}
        context={context}
        initialRules={correctionRules}
      />
      <DeleteRuleDialog
        rule={deleting}
        onClose={() => setDeleting(undefined)}
        onConfirm={(rule) => {
          setDeleting(undefined);
          void queueRuleDeletion(rule);
        }}
      />
      <EditRuleDialog
        key={
          editing
            ? `${editing.id}:${editing.revision}:${editingCorrectionOperation?.id ?? 'normal'}`
            : 'closed'
        }
        rule={editing}
        correctionOperation={editingCorrectionOperation}
        onClose={() => {
          setEditing(undefined);
          setEditingCorrectionOperation(undefined);
        }}
        activeGroupId={activeGroupId}
        groupName={groupName}
        groupSlug={groupSlug}
        context={context}
      />
      <Group mb="md" justify="space-between">
        <TextInput
          aria-label="Search rules"
          placeholder="Search rule names"
          leftSection={<IconSearch size={15} />}
          value={query}
          onChange={(event) => setQuery(event.currentTarget.value)}
          w={{ base: '100%', sm: 320 }}
        />
        <Group gap="xs">
          {orderChanged && (
            <>
              <Button
                variant="subtle"
                disabled={orderBusy}
                onClick={() => setOrderedRuleIds(providerOrder.map((rule) => rule.id))}
              >
                Cancel reorder
              </Button>
              <Button loading={orderBusy} onClick={() => void saveOrder()}>
                Save rule order
              </Button>
            </>
          )}
        </Group>
      </Group>
      {deleteNotice && !deleteError && (
        <Alert color="blue" title="Rule deletion" mb="md">
          {deleteNotice}
        </Alert>
      )}
      {deleteError && (
        <Alert color="red" title="Rule deletion could not continue" mb="md">
          {deleteError}
        </Alert>
      )}
      {rejectedRuleOperations.length > 0 && (
        <AppCard className="fm-subtle-panel" mb="md">
          <Text fw={700} mb="xs">
            Rejected rules
          </Text>
          <Text size="sm" c="dimmed" mb="sm">
            These rule changes were not created on the provider. Review the reason and submit a
            correction.
          </Text>
          <AppDataTable label="Rejected firewall rules">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Rule</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Changeset</Table.Th>
                <Table.Th>Action</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rejectedRuleOperations.map(({ changeSet, operation }) => (
                <Table.Tr key={`${changeSet.id}-${operation.id}`}>
                  <Table.Td>
                    <Text fw={650}>
                      {String(operation.payload.name ?? pendingOperationName(operation))}
                    </Text>
                    <Text size="xs" c="red">
                      Rejected by{' '}
                      {changeSet.rejected_by_display_name ??
                        changeSet.rejected_by_email ??
                        'an approver'}
                      : {changeSet.rejection_reason ?? 'No reason was provided.'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <span
                      className="fm-resource-state-notice fm-resource-state-rejected"
                      aria-label="Rejected"
                    >
                      <IconAlertTriangle size={16} stroke={2} />
                      <span>Rejected</span>
                    </span>
                  </Table.Td>
                  <Table.Td>{changeSet.title}</Table.Td>
                  <Table.Td>
                    <ActionButton
                      intent="secondary"
                      onClick={() => {
                        if (operation.kind === 'CREATE_RULE') {
                          setCorrectionRules([pendingRuleFromOperation(operation)]);
                          setCreating(true);
                          return;
                        }
                        const ruleId = String(operation.payload.rule_id ?? '');
                        const existing = context.rules.find((candidate) => candidate.id === ruleId);
                        if (existing) {
                          setEditingCorrectionOperation(operation);
                          setEditing(existing);
                        }
                      }}
                    >
                      Correct and resubmit
                    </ActionButton>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </AppDataTable>
        </AppCard>
      )}
      {pendingRuleOperations.length > 0 && (
        <AppCard className="fm-subtle-panel" mb="md">
          <Text fw={700} mb="xs">
            Rules awaiting approval
          </Text>
          <Text size="sm" c="dimmed" mb="sm">
            These rule changes are awaiting approval and are not on the provider yet.
          </Text>
          <AppDataTable label="Rules awaiting approval">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Rule</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Changeset</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {pendingRuleOperations.map(({ changeSet, operation }) => (
                <Table.Tr key={`${changeSet.id}-${operation.id}`}>
                  <Table.Td>
                    <Text fw={650}>
                      {String(operation.payload.name ?? pendingOperationName(operation))}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <AppStatusBadge value="PENDING" label="AWAITING APPROVAL" />
                  </Table.Td>
                  <Table.Td>{changeSet.title}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </AppDataTable>
        </AppCard>
      )}
      {pendingRuleOperations.length === 0 &&
      rejectedRuleOperations.length === 0 &&
      filtered.length === 0 ? (
        <AppEmptyState
          title={context.rules.length ? 'No matching rules' : 'No Group-owned rules'}
          description={
            context.rules.length
              ? 'Clear or refine the current search.'
              : 'Create a Changeset draft to add the first rule in this delegated category.'
          }
        />
      ) : (
        <div className="fm-rule-list" role="list" aria-label={`${groupName} access rules`}>
          {filtered.map((rule) => (
            <section
              key={rule.id}
              role="listitem"
              draggable={reorderEnabled && !orderBusy}
              aria-grabbed={draggedRuleId === rule.id}
              data-action={rule.action}
              className={`fm-rule-card${draggedRuleId === rule.id ? ' fm-rule-card-dragging' : ''}`}
              onDragStart={(event) => {
                setDraggedRuleId(rule.id);
                event.dataTransfer.effectAllowed = 'move';
                event.dataTransfer.setData('text/plain', rule.id);
              }}
              onDragOver={(event) => {
                if (reorderEnabled) event.preventDefault();
              }}
              onDrop={(event) => {
                event.preventDefault();
                const bounds = event.currentTarget.getBoundingClientRect();
                moveDraggedRule(rule.id, event.clientY > bounds.top + bounds.height / 2);
                setDraggedRuleId('');
              }}
              onDragEnd={() => setDraggedRuleId('')}
            >
              <div className="fm-rule-card-header">
                <div className="fm-rule-identity">
                  <div className="fm-rule-order" aria-label={`Rule order ${rule.position}`}>
                    <IconArrowsMoveVertical size={17} />
                    <span>
                      {
                        providerOrder[orderedRules.findIndex((item) => item.id === rule.id)]
                          ?.position
                      }
                    </span>
                  </div>
                  <div className="fm-rule-title-block">
                    <Group gap="xs" wrap="wrap" align="center">
                      <Text fw={750} className="fm-rule-title">
                        {rule.name}
                      </Text>
                      <AppStatusBadge
                        value={
                          rule.action === 'ALLOW'
                            ? 'SUCCESS'
                            : rule.action === 'BLOCK'
                              ? 'FAILED'
                              : 'WARNING'
                        }
                        label={rule.action}
                      />
                      {!rule.enabled && <AppStatusBadge value="DISABLED" />}
                    </Group>
                    <Text size="10px" c="dimmed">
                      Revision {rule.revision}
                    </Text>
                  </div>
                </div>
                <Group gap="xs" wrap="wrap" justify="flex-end">
                  <RuleFeatureIcons rule={rule} context={context} />
                  <ResourceStateNotice
                    state={rule.management_state}
                    firewallState={rule.firewall_state}
                    deploymentStatus={context.firewall_deployment_status}
                    policyDeviceAssignment={context.policy_device_assignment}
                    pending={trackedRuleOperations.some(
                      ({ changeSet, operation }) =>
                        pendingDeploymentState(changeSet.state, changeSet.approval_required) &&
                        operation.payload.rule_id === rule.id,
                    )}
                  />
                  {rule.drift_id && ['DRIFTED', 'CONFLICT'].includes(rule.management_state) && (
                    <AppTooltip label="Accept provider state" withArrow>
                      <Button
                        variant="subtle"
                        px={6}
                        aria-label={`Accept provider state for ${rule.name}`}
                        loading={acceptingDriftId === rule.drift_id}
                        disabled={Boolean(acceptingDriftId)}
                        onClick={(event) => {
                          event.stopPropagation();
                          void acceptRuleProviderState(rule.drift_id!);
                        }}
                      >
                        <IconCloudDownload size={17} />
                      </Button>
                    </AppTooltip>
                  )}
                  {activeRuleOperations.some(
                    ({ operation }) =>
                      operation.kind === 'DELETE_RULE' && operation.payload.rule_id === rule.id,
                  ) && <AppStatusBadge value="EXECUTING" label="Deleting" />}
                  <Button
                    variant="subtle"
                    px={6}
                    aria-label={`Edit ${rule.name}`}
                    disabled={
                      !context.provider_writable || !context.capabilities.includes('modify_rule')
                    }
                    onClick={(event) => {
                      event.stopPropagation();
                      setEditing(rule);
                    }}
                    onDragStart={(event) => event.preventDefault()}
                  >
                    <IconEdit size={15} />
                  </Button>
                  <Button
                    variant="subtle"
                    color="red"
                    px={6}
                    aria-label={`Delete ${rule.name}`}
                    disabled={
                      !context.provider_writable ||
                      !context.capabilities.includes('delete_rule') ||
                      deletePendingIds.includes(rule.id) ||
                      pendingDeleteRuleIds.has(rule.id)
                    }
                    onClick={() => setDeleting(rule)}
                    onDragStart={(event) => event.preventDefault()}
                  >
                    <IconTrash size={15} />
                  </Button>
                  {deletePendingIds.includes(rule.id) && (
                    <AppStatusBadge value="QUEUED" label="Queueing deletion" />
                  )}
                </Group>
              </div>
              <div className="fm-rule-flow">
                <RuleLane title="Source" tone="source">
                  <RuleFact label="Zones" values={rule.source_zones ?? []} />
                  <RuleFact label="Networks" values={rule.source_networks ?? []} />
                  <RuleFact label="Services / ports" values={rule.source_services ?? []} />
                </RuleLane>
                <div className="fm-rule-flow-arrow" aria-hidden="true">
                  <IconArrowRight size={20} />
                </div>
                <RuleLane title="Destination" tone="destination">
                  <RuleFact label="Zones" values={rule.destination_zones ?? []} />
                  <RuleFact label="Networks" values={rule.destination_networks ?? []} />
                  <RuleFact label="Services / ports" values={rule.destination_services ?? []} />
                  <RuleFact label="Applications" values={rule.applications ?? []} />
                  <RuleFact label="URLs" values={rule.urls ?? []} />
                </RuleLane>
              </div>
            </section>
          ))}
        </div>
      )}
      {query && context.capabilities.includes('reorder_rule') && (
        <Text size="xs" c="dimmed" mt="xs">
          Clear the search to drag and reorder the complete rule section.
        </Text>
      )}
      {orderError && (
        <Alert mt="md" color="red" title="Rule order could not be saved" role="alert">
          {orderError}
        </Alert>
      )}
      {acceptError && (
        <Alert mt="md" color="red" title="Provider state could not be accepted">
          {acceptError}
        </Alert>
      )}
      {orderQueued && (
        <Alert mt="md" color="blue" title="Rule order queued">
          Changeset {orderQueued.title} was created, preflighted, and submitted. Its status and
          details are available on the Changesets page.
        </Alert>
      )}
      <Alert
        mt="md"
        color="blue"
        icon={<IconArrowsMoveVertical size={18} />}
        title="Safe ordering boundary"
      >
        Drag an entire row to arrange this Group's rules, then save the order. Reordering never
        crosses the Group's provider section boundary.
      </Alert>
    </AppCard>
  );
}

function RuleFeatureIcons({
  rule,
  context,
}: {
  rule: DelegatedContext['rules'][number];
  context: DelegatedContext;
}) {
  const intrusion = (context.intrusion_policies ?? []).find(
    (item) => item.id === rule.intrusion_policy_id,
  );
  const variableSet = (context.variable_sets ?? []).find(
    (item) => item.id === rule.variable_set_id,
  );
  const filePolicy = (context.file_policies ?? []).find((item) => item.id === rule.file_policy_id);
  const features = [
    {
      key: 'logging',
      label: rule.logging === 'NONE' ? 'Logging disabled' : `Log at ${rule.logging.toLowerCase()}`,
      enabled: rule.logging !== 'NONE',
      Icon: IconFileDescription,
    },
    {
      key: 'intrusion',
      label: intrusion
        ? `Intrusion policy: ${intrusion.name}${variableSet ? ` · Variable set: ${variableSet.name}` : ''}`
        : 'No intrusion policy',
      enabled: Boolean(intrusion),
      Icon: IconShieldCheck,
    },
    {
      key: 'file-policy',
      label: filePolicy ? `File policy: ${filePolicy.name}` : 'No file policy',
      enabled: Boolean(filePolicy),
      Icon: IconFileTextShield,
    },
  ];
  return (
    <Group className="fm-rule-feature-icons" gap={4} wrap="nowrap" aria-label="Rule features">
      {features.map(({ key, label, enabled, Icon }) => (
        <AppTooltip key={key} label={label} withArrow>
          <span
            className={`fm-rule-feature-icon${enabled ? ' fm-rule-feature-icon-enabled' : ''}`}
            aria-label={label}
          >
            <Icon size={18} stroke={1.8} />
          </span>
        </AppTooltip>
      ))}
    </Group>
  );
}

function ResourceStateNotice({
  state,
  pending = false,
  firewallState,
  deploymentStatus,
  policyDeviceAssignment,
}: {
  state?: string;
  pending?: boolean;
  firewallState?: 'DEPLOYED' | 'UNDEPLOYED' | 'NOT_PRESENT' | 'UNKNOWN';
  deploymentStatus?: 'SUPPORTED' | 'NOT_AVAILABLE';
  policyDeviceAssignment?: 'ASSIGNED' | 'UNASSIGNED' | 'UNKNOWN';
}) {
  const currentState = state ?? 'UNKNOWN';
  const firewallStateVisible =
    Boolean(firewallState) &&
    (firewallState !== 'UNKNOWN' || policyDeviceAssignment === 'ASSIGNED');
  const unverified = deploymentStatus === 'NOT_AVAILABLE' && !firewallStateVisible;
  const confirmedDeployed = !pending && firewallStateVisible && firewallState === 'DEPLOYED';
  const label = pending
    ? 'Deployment pending: this resource has an unexecuted or in-progress Changeset.'
    : firewallStateVisible && firewallState
      ? firewallStateLabel(firewallState)
      : unverified
        ? 'Firewall deployment has not been verified. Managed means synchronized to FMC/SCC only.'
        : resourceStateLabel(currentState);
  if (!pending && currentState === 'MANAGED' && !unverified && !firewallStateVisible) return null;
  return (
    <AppTooltip label={label} withArrow>
      <span
        className={`fm-resource-state-notice${confirmedDeployed ? ' fm-resource-state-deployed' : ''}`}
        aria-label={label}
      >
        {confirmedDeployed ? (
          <IconCircleCheck size={16} stroke={2} />
        ) : (
          <IconAlertTriangle size={16} stroke={2} />
        )}
        <span>
          {pending
            ? 'Deployment pending'
            : firewallStateVisible && firewallState
              ? firewallStateChip(firewallState)
              : unverified
                ? 'Firewall unknown'
                : resourceStateChip(currentState)}
        </span>
      </span>
    </AppTooltip>
  );
}

function pendingDeploymentState(state: string, approvalRequired = false) {
  return ['QUEUED', 'EXECUTING'].includes(state) || (state === 'READY' && !approvalRequired);
}

function resourceStateLabel(state: string) {
  switch (state) {
    case 'OBSERVED':
      return 'Imported from the provider; not deployed from this application.';
    case 'UNMANAGED':
      return 'Provider resource is not managed by this application.';
    case 'DRIFTED':
      return 'Provider state differs from the application state.';
    case 'MISSING':
      return 'Resource is missing from the provider.';
    case 'CONFLICT':
      return 'Resource has a synchronization conflict requiring review.';
    case 'PENDING_ADOPTION':
      return 'Resource is waiting to be adopted by the application.';
    default:
      return `Provider state: ${state.toLowerCase()}`;
  }
}

function resourceStateChip(state: string) {
  return state === 'OBSERVED' ? 'Not deployed' : humanize(state);
}

function firewallStateLabel(state: 'DEPLOYED' | 'UNDEPLOYED' | 'NOT_PRESENT' | 'UNKNOWN') {
  switch (state) {
    case 'DEPLOYED':
      return 'This resource is present in the application and has been confirmed deployed to the firewall.';
    case 'UNDEPLOYED':
      return 'The provider configuration contains this resource, but the change has not yet been confirmed deployed to the firewall.';
    case 'NOT_PRESENT':
      return 'This resource is not present on the firewall.';
    default:
      return 'The application has not confirmed whether this resource is deployed to the firewall.';
  }
}

function firewallStateChip(state: 'DEPLOYED' | 'UNDEPLOYED' | 'NOT_PRESENT' | 'UNKNOWN') {
  switch (state) {
    case 'DEPLOYED':
      return 'Deployed';
    case 'UNDEPLOYED':
      return 'Deployment pending';
    default:
      return `Firewall ${humanize(state)}`;
  }
}

function CreateRuleDialog({
  opened,
  onClose,
  activeGroupId,
  groupName,
  groupSlug,
  context,
  initialRules = [],
}: {
  opened: boolean;
  onClose: () => void;
  activeGroupId: string;
  groupName: string;
  groupSlug: string;
  context: DelegatedContext;
  initialRules?: PendingRule[];
}) {
  const [changeSetName, setChangeSetName] = useState(() => defaultRuleChangeSetName(groupName));
  const [name, setName] = useState('');
  const [action, setAction] = useState('ALLOW');
  const [enabled, setEnabled] = useState('true');
  const [logging, setLogging] = useState<PendingRule['logging']>('NONE');
  const [intrusionPolicyId, setIntrusionPolicyId] = useState<string | null>(null);
  const [variableSetId, setVariableSetId] = useState<string | null>(null);
  const [filePolicyId, setFilePolicyId] = useState<string | null>(null);
  const [sourceZoneIds, setSourceZoneIds] = useState<string[]>([]);
  const [destinationZoneIds, setDestinationZoneIds] = useState<string[]>([]);
  const [sourceObjectIds, setSourceObjectIds] = useState<string[]>([]);
  const [destinationObjectIds, setDestinationObjectIds] = useState<string[]>([]);
  const [sourcePortObjectIds, setSourcePortObjectIds] = useState<string[]>([]);
  const [destinationPortObjectIds, setDestinationPortObjectIds] = useState<string[]>([]);
  const [applicationObjectIds, setApplicationObjectIds] = useState<string[]>([]);
  const orderedExistingRules = [...context.rules].sort(
    (left, right) => left.position - right.position,
  );
  const [placement, setPlacement] = useState<string | null>(
    defaultRulePlacement(orderedExistingRules),
  );
  const [rules, setRules] = useState<PendingRule[]>(initialRules);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [prepared, setPrepared] = useState<ChangeSet>();
  const [queued, setQueued] = useState<ChangeSet>();
  const [verificationStarted, setVerificationStarted] = useState(false);
  const delegatedCategoryId = context.categories[0]?.id ?? orderedExistingRules[0]?.category_id;

  useEffect(() => {
    if (action !== 'ALLOW') {
      setIntrusionPolicyId(null);
      setVariableSetId(null);
      setFilePolicyId(null);
    }
  }, [action]);

  const sourceZones = context.zones
    .filter((zone) => zone.direction !== 'DESTINATION')
    .map(selectOption);
  const destinationZones = context.zones
    .filter((zone) => zone.direction !== 'SOURCE')
    .map(selectOption);
  const ruleObjectIds = new Set([
    ...sourceObjectIds,
    ...destinationObjectIds,
    ...sourcePortObjectIds,
    ...destinationPortObjectIds,
    ...applicationObjectIds,
  ]);
  const ruleObjects = context.objects.filter(
    (object) => object.access_permission === 'use' || ruleObjectIds.has(object.id),
  );
  const networkObjects = ruleObjects
    .filter((object) => ['NETWORK', 'NETWORK_GROUP'].includes(object.object_type))
    .map(selectOption);
  const portObjects = ruleObjects
    .filter((object) => ['PORT_SERVICE', 'PORT_SERVICE_GROUP'].includes(object.object_type))
    .map(selectOption);
  const intrusionPolicies = (context.intrusion_policies ?? []).map((item) => ({
    value: item.id,
    label: item.name,
  }));
  const variableSets = (context.variable_sets ?? []).map((item) => ({
    value: item.id,
    label: item.is_default ? `${item.name} (default)` : item.name,
  }));
  const filePolicies = (context.file_policies ?? []).map((item) => ({
    value: item.id,
    label: item.name,
  }));
  const clearRuleFields = () => {
    setName('');
    setAction('ALLOW');
    setEnabled('true');
    setLogging('NONE');
    setIntrusionPolicyId(null);
    setVariableSetId(null);
    setFilePolicyId(null);
    setSourceZoneIds([]);
    setDestinationZoneIds([]);
    setSourceObjectIds([]);
    setDestinationObjectIds([]);
    setSourcePortObjectIds([]);
    setDestinationPortObjectIds([]);
    setApplicationObjectIds([]);
    setPlacement(defaultRulePlacement(orderedExistingRules));
  };
  const resetAndClose = () => {
    if (busy) return;
    clearRuleFields();
    setChangeSetName(defaultRuleChangeSetName(groupName));
    setRules([]);
    setError('');
    setPrepared(undefined);
    setQueued(undefined);
    setVerificationStarted(false);
    onClose();
  };
  const addRule = () => {
    const cleanName = name.trim();
    if (!cleanName) return;
    const scopeError = ruleScopeError(
      sourceZoneIds,
      destinationZoneIds,
      sourceObjectIds,
      destinationObjectIds,
    );
    if (scopeError) {
      setError(scopeError);
      return;
    }
    const providerName = providerRuleName(groupSlug, cleanName).toLocaleLowerCase();
    if (
      rules.some(
        (rule) => providerRuleName(groupSlug, rule.name).toLocaleLowerCase() === providerName,
      )
    ) {
      setError('Each rule in this Changeset must have a unique name.');
      return;
    }
    setRules((current) => [
      ...current,
      {
        id: `${Date.now()}-${current.length}`,
        name: cleanName,
        action,
        enabled: enabled === 'true',
        logging,
        intrusion_policy_id: intrusionPolicyId ?? undefined,
        variable_set_id: variableSetId ?? undefined,
        file_policy_id: filePolicyId ?? undefined,
        source_zone_ids: sourceZoneIds,
        destination_zone_ids: destinationZoneIds,
        source_object_ids: sourceObjectIds,
        destination_object_ids: destinationObjectIds,
        source_port_object_ids: sourcePortObjectIds,
        destination_port_object_ids: destinationPortObjectIds,
        application_object_ids: applicationObjectIds,
        ...(orderedExistingRules.length
          ? rulePlacementPayload(placement, orderedExistingRules)
          : {}),
        ...(delegatedCategoryId ? { category_id: delegatedCategoryId } : {}),
      },
    ]);
    setError('');
    clearRuleFields();
  };
  const editRule = (rule: PendingRule) => {
    setName(rule.name);
    setAction(rule.action);
    setEnabled(rule.enabled === false ? 'false' : 'true');
    setLogging(rule.logging ?? 'NONE');
    setSourceZoneIds(rule.source_zone_ids);
    setDestinationZoneIds(rule.destination_zone_ids);
    setSourceObjectIds(rule.source_object_ids);
    setDestinationObjectIds(rule.destination_object_ids);
    setSourcePortObjectIds(rule.source_port_object_ids);
    setDestinationPortObjectIds(rule.destination_port_object_ids);
    setApplicationObjectIds(rule.application_object_ids);
    setIntrusionPolicyId(rule.intrusion_policy_id ?? null);
    setVariableSetId(rule.variable_set_id ?? null);
    setFilePolicyId(rule.file_policy_id ?? null);
    setPlacement(rulePlacementValue(rule));
    setRules((current) => current.filter((item) => item.id !== rule.id));
    setError('');
  };
  const prepare = async () => {
    setBusy(true);
    setVerificationStarted(true);
    setError('');
    try {
      const draft = await createChangeSet(
        activeGroupId,
        context.policy.id,
        changeSetName.trim(),
        `Create ${rules.length} rule${rules.length === 1 ? '' : 's'} from the Rules workspace.`,
      );
      let withRules = await addDraftCategory(draft.id, activeGroupId, context.policy.id);
      for (const rule of [...rules].reverse()) {
        const payload: Record<string, unknown> = { ...rule };
        delete payload.id;
        withRules = await addDraftRule(draft.id, activeGroupId, payload);
      }
      const validated = await changeSetAction(withRules.id, activeGroupId, 'preflight');
      setPrepared(validated);
      if (validated.state !== 'READY') {
        setError(rulePreflightError(validated));
        return;
      }
      if (validated.approval_required) {
        setError(
          'This Group requires approval before rule changes can be submitted. Close this dialog and have an authorized approver approve the Changeset.',
        );
        return;
      }
      setQueued(await changeSetAction(validated.id, activeGroupId, 'execute'));
    } catch (reason) {
      setError(ruleDialogError(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Dialog
        opened={opened && !verificationStarted}
        onClose={resetAndClose}
        title="Create firewall rule"
        centered
        size="xl"
        classNames={{ content: 'fm-object-dialog', body: 'fm-object-dialog-body' }}
        closeOnClickOutside={!busy}
        closeOnEscape={!busy}
      >
        <Stack gap="md">
          {!queued && (
            <>
              <Text size="sm" c="dimmed">
                Add one or more rules for {groupName} and {context.policy.name}. One Changeset is
                created and preflighted without leaving this page.
              </Text>
              <TextInput
                label="Changeset name"
                value={changeSetName}
                onChange={(event) => setChangeSetName(event.currentTarget.value)}
                disabled={busy}
              />
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <TextInput
                  label="Rule name"
                  value={name}
                  onChange={(event) => setName(event.currentTarget.value)}
                  disabled={busy}
                  description={
                    name.trim() ? `Provider name: ${providerRuleName(groupSlug, name)}` : undefined
                  }
                />
                <Select
                  label="Action"
                  value={action}
                  onChange={(value) => {
                    const next = value ?? 'ALLOW';
                    setAction(next);
                    if (next === 'BLOCK' && logging === 'END') setLogging('BEGIN');
                    if (next === 'MONITOR') setLogging('END');
                  }}
                  data={['ALLOW', 'BLOCK', 'TRUST', 'MONITOR']}
                  disabled={busy}
                />
                <Select
                  label="Rule status"
                  value={enabled}
                  onChange={(value) => {
                    const next = value ?? 'true';
                    setEnabled(next);
                    if (next === 'true' && intrusionPolicyId && !variableSetId) {
                      const selected = (context.intrusion_policies ?? []).find(
                        (item) => item.id === intrusionPolicyId,
                      );
                      setVariableSetId(selected?.default_variable_set_id ?? null);
                    }
                  }}
                  data={[
                    { value: 'true', label: 'Enabled' },
                    { value: 'false', label: 'Disabled' },
                  ]}
                  disabled={busy}
                />
                <Select
                  label="Logging"
                  value={logging}
                  onChange={(value) => setLogging(value ?? 'NONE')}
                  data={
                    action === 'BLOCK'
                      ? [
                          { value: 'NONE', label: 'Do not log' },
                          { value: 'BEGIN', label: 'Log at beginning' },
                        ]
                      : action === 'MONITOR'
                        ? [{ value: 'END', label: 'Log at end' }]
                        : [
                            { value: 'NONE', label: 'Do not log' },
                            { value: 'BEGIN', label: 'Log at beginning' },
                            { value: 'END', label: 'Log at end' },
                          ]
                  }
                  disabled={busy}
                />
                <Select
                  clearable={action !== 'ALLOW' || enabled !== 'true' || !intrusionPolicyId}
                  searchable
                  label="Intrusion policy"
                  placeholder="No intrusion policy"
                  value={intrusionPolicyId}
                  onChange={(value) => {
                    setIntrusionPolicyId(value);
                    const selected = (context.intrusion_policies ?? []).find(
                      (item) => item.id === value,
                    );
                    if (value && enabled === 'true') {
                      setVariableSetId(selected?.default_variable_set_id ?? null);
                    } else if (!value) {
                      setVariableSetId(null);
                    }
                  }}
                  data={intrusionPolicies}
                  disabled={busy || action !== 'ALLOW'}
                />
                <Select
                  clearable={action !== 'ALLOW' || enabled !== 'true' || !intrusionPolicyId}
                  searchable
                  label="Variable set"
                  placeholder="Select variable set"
                  value={variableSetId}
                  onChange={(value) => {
                    if (value) setVariableSetId(value);
                    else if (enabled === 'true' && intrusionPolicyId) {
                      setVariableSetId(
                        (context.intrusion_policies ?? []).find(
                          (item) => item.id === intrusionPolicyId,
                        )?.default_variable_set_id ?? null,
                      );
                    } else setVariableSetId(null);
                  }}
                  data={variableSets}
                  disabled={busy || action !== 'ALLOW' || !intrusionPolicyId}
                />
                <Select
                  clearable
                  searchable
                  label="File policy"
                  placeholder="No file policy"
                  value={filePolicyId}
                  onChange={setFilePolicyId}
                  data={filePolicies}
                  disabled={busy || action !== 'ALLOW' || enabled !== 'true'}
                />
              </SimpleGrid>
              {orderedExistingRules.length > 0 && (
                <Select
                  required
                  label="Place new rule"
                  placeholder="Choose where this rule belongs"
                  value={placement}
                  onChange={setPlacement}
                  data={rulePlacementOptions(orderedExistingRules)}
                  disabled={busy}
                  description="The new rule will remain inside this Group's rule section."
                />
              )}
              <SimpleGrid cols={{ base: 1, md: 2 }}>
                <MultiSelect
                  searchable
                  label="Source zones"
                  data={sourceZones}
                  value={sourceZoneIds}
                  onChange={setSourceZoneIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Destination zones"
                  data={destinationZones}
                  value={destinationZoneIds}
                  onChange={setDestinationZoneIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Source networks"
                  data={networkObjects}
                  value={sourceObjectIds}
                  onChange={setSourceObjectIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Destination networks"
                  data={networkObjects}
                  value={destinationObjectIds}
                  onChange={setDestinationObjectIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Source services / ports"
                  data={portObjects}
                  value={sourcePortObjectIds}
                  onChange={setSourcePortObjectIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Destination services / ports"
                  data={portObjects}
                  value={destinationPortObjectIds}
                  onChange={setDestinationPortObjectIds}
                  disabled={busy}
                />
                <ApplicationSelector
                  objects={ruleObjects}
                  selectedIds={applicationObjectIds}
                  onChange={setApplicationObjectIds}
                  disabled={busy}
                />
              </SimpleGrid>
              <Button
                variant="light"
                disabled={!name.trim() || busy || (orderedExistingRules.length > 0 && !placement)}
                onClick={addRule}
              >
                Add rule to Changeset
              </Button>
              {rules.length > 0 && (
                <div className="fm-object-basket">
                  <AppDataTable label="Rules in this Changeset">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Rule</Table.Th>
                        <Table.Th>Action</Table.Th>
                        <Table.Th>Elements</Table.Th>
                        <Table.Th>Placement</Table.Th>
                        <Table.Th className="fm-object-actions">Actions</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {rules.map((rule) => (
                        <Table.Tr key={rule.id}>
                          <Table.Td>{providerRuleName(groupSlug, rule.name)}</Table.Td>
                          <Table.Td>{rule.action}</Table.Td>
                          <Table.Td>{ruleElementCount(rule)} selected</Table.Td>
                          <Table.Td>{rulePlacementLabel(rule, orderedExistingRules)}</Table.Td>
                          <Table.Td className="fm-object-actions">
                            <Group gap={4} wrap="wrap">
                              <Button
                                size="xs"
                                variant="subtle"
                                px={6}
                                onClick={() => editRule(rule)}
                              >
                                Edit
                              </Button>
                              <Button
                                size="xs"
                                variant="subtle"
                                px={6}
                                onClick={() =>
                                  setRules((current) =>
                                    current.filter((item) => item.id !== rule.id),
                                  )
                                }
                              >
                                Remove
                              </Button>
                            </Group>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </AppDataTable>
                </div>
              )}
            </>
          )}
          {error && (
            <Alert
              color={prepared?.approval_required ? 'yellow' : 'red'}
              title={
                prepared?.approval_required
                  ? 'Approval required'
                  : 'Rule creation could not continue'
              }
              role="alert"
            >
              {error}
            </Alert>
          )}
          {busy && !prepared && !queued && (
            <Alert color="blue" title="Checking and saving rules">
              Validating permissions and provider values, then submitting the Changeset.
            </Alert>
          )}
          {prepared && !queued && (
            <AppCard className="fm-subtle-panel">
              <Text fw={700}>
                {prepared.approval_required
                  ? 'Changeset submitted'
                  : prepared.state === 'READY'
                    ? 'Ready to create'
                    : 'Preflight result'}
              </Text>
              <Text size="sm" mt={5}>
                {prepared.title} · {rules.length} rule operation
                {rules.length === 1 ? '' : 's'}
              </Text>
              <Text size="xs" c="dimmed" mt={5}>
                {context.provider_name} ({context.provider_type.toUpperCase()}) ·{' '}
                {context.policy.name} · {groupName}
              </Text>
              <AppStatusBadge
                value={prepared.approval_required ? 'PENDING' : prepared.state}
                label={prepared.approval_required ? 'AWAITING APPROVAL' : undefined}
              />
            </AppCard>
          )}
          {queued && (
            <Alert color="blue" title="Rule creation queued">
              Changeset {queued.title} is queued against {context.provider_name}. Provider
              deployment is not started and may later include pending changes outside this
              Changeset. The rules will appear after execution and synchronization complete.
            </Alert>
          )}
          <Group justify="flex-end">
            {prepared &&
              !queued &&
              !prepared.approval_required &&
              (prepared.state !== 'READY' || Boolean(error)) && (
                <Button
                  variant="light"
                  onClick={() => {
                    setPrepared(undefined);
                    setError('');
                    setVerificationStarted(false);
                  }}
                  disabled={busy}
                >
                  Back and edit rules
                </Button>
              )}
            <Button variant="subtle" onClick={resetAndClose} disabled={busy}>
              {queued || prepared ? 'Close' : 'Cancel'}
            </Button>
            {!prepared && !queued && (
              <Button
                loading={busy}
                disabled={!changeSetName.trim() || rules.length === 0}
                onClick={() => void prepare()}
              >
                Save {rules.length} rule{rules.length === 1 ? '' : 's'}
              </Button>
            )}
          </Group>
        </Stack>
      </Dialog>
      <Dialog
        opened={verificationStarted}
        onClose={resetAndClose}
        title="Rule submission"
        centered
        size="lg"
        closeOnClickOutside={!busy}
        closeOnEscape={!busy}
      >
        <Stack gap="md">
          {busy && (
            <Alert color="blue" title="Checking and saving rules">
              Validating permissions and provider values, then submitting the Changeset.
            </Alert>
          )}
          {error && (
            <Alert
              color={prepared?.approval_required ? 'yellow' : 'red'}
              title={
                prepared?.approval_required
                  ? 'Approval required'
                  : 'Rule creation could not continue'
              }
            >
              {error}
            </Alert>
          )}
          {prepared && (
            <AppCard className="fm-subtle-panel">
              <Text fw={700}>
                {prepared.approval_required
                  ? 'Changeset submitted'
                  : prepared.state === 'READY'
                    ? 'Rule submission accepted'
                    : 'Validation failed'}
              </Text>
              <Text size="sm" mt={5}>
                {prepared.title} · {rules.length} rule operation{rules.length === 1 ? '' : 's'}
              </Text>
              <Group justify="space-between" align="center" mt={5}>
                <Text size="xs" c="dimmed">
                  {context.provider_name} ({context.provider_type.toUpperCase()}) ·{' '}
                  {context.policy.name} · {groupName}
                </Text>
                <AppStatusBadge
                  value={prepared.approval_required ? 'PENDING' : prepared.state}
                  label={prepared.approval_required ? 'AWAITING APPROVAL' : undefined}
                />
              </Group>
            </AppCard>
          )}
          {queued && (
            <Alert color="blue" title="Rule changes submitted">
              Changeset {queued.title} was submitted and will appear on the Changesets page.
            </Alert>
          )}
          <Group justify="flex-end">
            {prepared &&
              !queued &&
              !prepared.approval_required &&
              (prepared.state !== 'READY' || Boolean(error)) && (
                <Button
                  variant="light"
                  onClick={() => {
                    setPrepared(undefined);
                    setError('');
                    setVerificationStarted(false);
                  }}
                  disabled={busy}
                >
                  Back and edit rules
                </Button>
              )}
            <Button variant="subtle" onClick={resetAndClose} disabled={busy}>
              Close
            </Button>
          </Group>
        </Stack>
      </Dialog>
    </>
  );
}

function EditRuleDialog({
  rule,
  onClose,
  correctionOperation,
  activeGroupId,
  groupName,
  groupSlug,
  context,
}: {
  rule: DelegatedContext['rules'][number] | undefined;
  onClose: () => void;
  correctionOperation?: ChangeSet['operations'][number];
  activeGroupId: string;
  groupName: string;
  groupSlug: string;
  context: DelegatedContext;
}) {
  const correctionPayload = correctionOperation?.payload;
  const payloadIds = (key: string, fallback: string[]) =>
    Array.isArray(correctionPayload?.[key]) ? correctionPayload[key].map(String) : fallback;
  const [name, setName] = useState(() =>
    rule ? editableRuleName(groupSlug, String(correctionPayload?.name ?? rule.name)) : '',
  );
  const [action, setAction] = useState(() =>
    String(correctionPayload?.action ?? rule?.action ?? 'ALLOW'),
  );
  const [enabled, setEnabled] = useState(() =>
    (correctionPayload?.enabled ?? rule?.enabled ?? true) ? 'true' : 'false',
  );
  const [logging, setLogging] = useState<PendingRule['logging']>(() =>
    String(correctionPayload?.action ?? rule?.action) === 'BLOCK'
      ? String(correctionPayload?.logging ?? rule?.logging) === 'BEGIN'
        ? 'BEGIN'
        : 'NONE'
      : String(correctionPayload?.action ?? rule?.action) === 'MONITOR'
        ? 'END'
        : ((correctionPayload?.logging ?? rule?.logging ?? 'NONE') as PendingRule['logging']),
  );
  const [intrusionPolicyId, setIntrusionPolicyId] = useState<string | null>(
    correctionPayload?.intrusion_policy_id
      ? String(correctionPayload.intrusion_policy_id)
      : (rule?.intrusion_policy_id ?? null),
  );
  const [variableSetId, setVariableSetId] = useState<string | null>(() => {
    if (correctionPayload?.variable_set_id) return String(correctionPayload.variable_set_id);
    if (correctionPayload?.enabled !== false && correctionPayload?.intrusion_policy_id) {
      return (
        (context.intrusion_policies ?? []).find(
          (item) => item.id === String(correctionPayload.intrusion_policy_id),
        )?.default_variable_set_id ?? null
      );
    }
    if (rule?.variable_set_id) return rule.variable_set_id;
    if (rule?.enabled !== false && rule?.intrusion_policy_id) {
      return (
        (context.intrusion_policies ?? []).find((item) => item.id === rule.intrusion_policy_id)
          ?.default_variable_set_id ?? null
      );
    }
    return null;
  });
  const [filePolicyId, setFilePolicyId] = useState<string | null>(
    correctionPayload?.file_policy_id
      ? String(correctionPayload.file_policy_id)
      : (rule?.file_policy_id ?? null),
  );
  useEffect(() => {
    if (action !== 'ALLOW') {
      setIntrusionPolicyId(null);
      setVariableSetId(null);
      setFilePolicyId(null);
    }
  }, [action]);
  const [sourceZoneIds, setSourceZoneIds] = useState<string[]>(() =>
    payloadIds('source_zone_ids', rule ? idsForNames(context.zones, rule.source_zones ?? []) : []),
  );
  const [destinationZoneIds, setDestinationZoneIds] = useState<string[]>(() =>
    payloadIds(
      'destination_zone_ids',
      rule ? idsForNames(context.zones, rule.destination_zones ?? []) : [],
    ),
  );
  const [sourceObjectIds, setSourceObjectIds] = useState<string[]>(() =>
    payloadIds(
      'source_object_ids',
      rule ? idsForNames(context.objects, rule.source_networks ?? []) : [],
    ),
  );
  const [destinationObjectIds, setDestinationObjectIds] = useState<string[]>(() =>
    payloadIds(
      'destination_object_ids',
      rule ? idsForNames(context.objects, rule.destination_networks ?? []) : [],
    ),
  );
  const [sourcePortObjectIds, setSourcePortObjectIds] = useState<string[]>(() =>
    payloadIds(
      'source_port_object_ids',
      rule ? idsForNames(context.objects, rule.source_services ?? []) : [],
    ),
  );
  const [destinationPortObjectIds, setDestinationPortObjectIds] = useState<string[]>(() =>
    payloadIds(
      'destination_port_object_ids',
      rule ? idsForNames(context.objects, rule.destination_services ?? []) : [],
    ),
  );
  const [applicationObjectIds, setApplicationObjectIds] = useState<string[]>(() =>
    payloadIds(
      'application_object_ids',
      rule
        ? (rule.application_object_ids?.map(String) ??
            idsForNames(context.objects, rule.applications ?? []))
        : [],
    ),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [prepared, setPrepared] = useState<ChangeSet>();
  const [queued, setQueued] = useState<ChangeSet>();
  const [verificationStarted, setVerificationStarted] = useState(false);
  const sourceZones = context.zones
    .filter((zone) => zone.direction !== 'DESTINATION')
    .map(selectOption);
  const destinationZones = context.zones
    .filter((zone) => zone.direction !== 'SOURCE')
    .map(selectOption);
  const ruleObjectIds = new Set([
    ...sourceObjectIds,
    ...destinationObjectIds,
    ...sourcePortObjectIds,
    ...destinationPortObjectIds,
    ...applicationObjectIds,
  ]);
  const ruleObjects = context.objects.filter(
    (object) => object.access_permission === 'use' || ruleObjectIds.has(object.id),
  );
  const networkObjects = ruleObjects
    .filter((object) => ['NETWORK', 'NETWORK_GROUP'].includes(object.object_type))
    .map(selectOption);
  const portObjects = ruleObjects
    .filter((object) => ['PORT_SERVICE', 'PORT_SERVICE_GROUP'].includes(object.object_type))
    .map(selectOption);
  const intrusionPolicies = (context.intrusion_policies ?? []).map((item) => ({
    value: item.id,
    label: item.name,
  }));
  const variableSets = (context.variable_sets ?? []).map((item) => ({
    value: item.id,
    label: item.is_default ? `${item.name} (default)` : item.name,
  }));
  const filePolicies = (context.file_policies ?? []).map((item) => ({
    value: item.id,
    label: item.name,
  }));

  const close = () => {
    if (busy) return;
    setError('');
    setPrepared(undefined);
    setQueued(undefined);
    setVerificationStarted(false);
    onClose();
  };
  const prepare = async () => {
    if (!rule || !name.trim()) return;
    const scopeError = ruleScopeError(
      sourceZoneIds,
      destinationZoneIds,
      sourceObjectIds,
      destinationObjectIds,
    );
    if (scopeError) {
      setError(scopeError);
      return;
    }
    setBusy(true);
    setVerificationStarted(true);
    setError('');
    try {
      const draft = await createChangeSet(
        activeGroupId,
        context.policy.id,
        `${groupName} rule ${correctionOperation ? 'correction' : 'update'} · ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`,
        `${correctionOperation ? 'Correct and resubmit' : 'Update'} ${rule.name} from the Rules workspace.`,
      );
      const withRule = await addDraftRule(
        draft.id,
        activeGroupId,
        {
          rule_id: String(correctionPayload?.rule_id ?? rule.id),
          name: providerRuleName(groupSlug, name),
          action,
          enabled: enabled === 'true',
          logging,
          category_id: context.categories[0]?.id ?? rule.category_id ?? undefined,
          intrusion_policy_id: intrusionPolicyId ?? undefined,
          variable_set_id: variableSetId ?? undefined,
          file_policy_id: filePolicyId ?? undefined,
          source_zone_ids: sourceZoneIds,
          destination_zone_ids: destinationZoneIds,
          source_object_ids: sourceObjectIds,
          destination_object_ids: destinationObjectIds,
          source_port_object_ids: sourcePortObjectIds,
          destination_port_object_ids: destinationPortObjectIds,
          application_object_ids: applicationObjectIds,
        },
        'MODIFY_RULE',
      );
      const validated = await changeSetAction(withRule.id, activeGroupId, 'preflight');
      setPrepared(validated);
      if (validated.state !== 'READY') {
        setError(rulePreflightError(validated));
        return;
      }
      if (validated.approval_required) {
        setError(
          'This Group requires approval before rule changes can be submitted. Close this dialog and have an authorized approver approve the Changeset.',
        );
        return;
      }
      setQueued(await changeSetAction(validated.id, activeGroupId, 'execute'));
    } catch (reason) {
      setError(ruleDialogError(reason));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Dialog
        opened={Boolean(rule) && !verificationStarted}
        onClose={close}
        title="Edit firewall rule"
        centered
        size="xl"
        classNames={{ content: 'fm-object-dialog', body: 'fm-object-dialog-body' }}
        closeOnClickOutside={!busy}
        closeOnEscape={!busy}
      >
        <Stack gap="md">
          {rule && !prepared && !queued && (
            <>
              <Text size="sm" c="dimmed">
                Update this Group-owned rule without leaving the Rules workspace.
              </Text>
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <TextInput
                  label="Rule name"
                  value={name}
                  onChange={(event) => setName(event.currentTarget.value)}
                  description={
                    name.trim() ? `Provider name: ${providerRuleName(groupSlug, name)}` : undefined
                  }
                  disabled={busy}
                />
                <Select
                  label="Action"
                  value={action}
                  onChange={(value) => {
                    const next = value ?? 'ALLOW';
                    setAction(next);
                    if (next === 'BLOCK' && logging === 'END') setLogging('BEGIN');
                    if (next === 'MONITOR') setLogging('END');
                  }}
                  data={['ALLOW', 'BLOCK', 'TRUST', 'MONITOR']}
                  disabled={busy}
                />
                <Select
                  label="Rule status"
                  value={enabled}
                  onChange={(value) => {
                    const next = value ?? 'true';
                    setEnabled(next);
                    if (next === 'true' && intrusionPolicyId && !variableSetId) {
                      const selected = (context.intrusion_policies ?? []).find(
                        (item) => item.id === intrusionPolicyId,
                      );
                      setVariableSetId(selected?.default_variable_set_id ?? null);
                    }
                  }}
                  data={[
                    { value: 'true', label: 'Enabled' },
                    { value: 'false', label: 'Disabled' },
                  ]}
                  disabled={busy}
                />
                <Select
                  label="Logging"
                  value={logging}
                  onChange={(value) => setLogging(value ?? 'NONE')}
                  data={
                    action === 'BLOCK'
                      ? [
                          { value: 'NONE', label: 'Do not log' },
                          { value: 'BEGIN', label: 'Log at beginning' },
                        ]
                      : action === 'MONITOR'
                        ? [{ value: 'END', label: 'Log at end' }]
                        : [
                            { value: 'NONE', label: 'Do not log' },
                            { value: 'BEGIN', label: 'Log at beginning' },
                            { value: 'END', label: 'Log at end' },
                          ]
                  }
                  disabled={busy}
                />
                <Select
                  clearable={action !== 'ALLOW' || enabled !== 'true' || !intrusionPolicyId}
                  searchable
                  label="Intrusion policy"
                  placeholder="No intrusion policy"
                  value={intrusionPolicyId}
                  onChange={(value) => {
                    setIntrusionPolicyId(value);
                    const selected = (context.intrusion_policies ?? []).find(
                      (item) => item.id === value,
                    );
                    if (value) setVariableSetId(selected?.default_variable_set_id ?? null);
                    else setVariableSetId(null);
                  }}
                  data={intrusionPolicies}
                  disabled={busy || action !== 'ALLOW'}
                />
                <Select
                  clearable={action !== 'ALLOW' || enabled !== 'true' || !intrusionPolicyId}
                  searchable
                  label="Variable set"
                  placeholder="Select variable set"
                  value={variableSetId}
                  onChange={(value) => {
                    if (value) setVariableSetId(value);
                    else if (enabled === 'true' && intrusionPolicyId) {
                      setVariableSetId(
                        (context.intrusion_policies ?? []).find(
                          (item) => item.id === intrusionPolicyId,
                        )?.default_variable_set_id ?? null,
                      );
                    } else setVariableSetId(null);
                  }}
                  data={variableSets}
                  disabled={busy || action !== 'ALLOW' || !intrusionPolicyId}
                />
                <Select
                  clearable
                  searchable
                  label="File policy"
                  placeholder="No file policy"
                  value={filePolicyId}
                  onChange={setFilePolicyId}
                  data={filePolicies}
                  disabled={busy || action !== 'ALLOW' || enabled !== 'true'}
                />
              </SimpleGrid>
              <SimpleGrid cols={{ base: 1, md: 2 }}>
                <MultiSelect
                  searchable
                  label="Source zones"
                  data={sourceZones}
                  value={sourceZoneIds}
                  onChange={setSourceZoneIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Destination zones"
                  data={destinationZones}
                  value={destinationZoneIds}
                  onChange={setDestinationZoneIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Source networks"
                  data={networkObjects}
                  value={sourceObjectIds}
                  onChange={setSourceObjectIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Destination networks"
                  data={networkObjects}
                  value={destinationObjectIds}
                  onChange={setDestinationObjectIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Source services / ports"
                  data={portObjects}
                  value={sourcePortObjectIds}
                  onChange={setSourcePortObjectIds}
                  disabled={busy}
                />
                <MultiSelect
                  searchable
                  label="Destination services / ports"
                  data={portObjects}
                  value={destinationPortObjectIds}
                  onChange={setDestinationPortObjectIds}
                  disabled={busy}
                />
                <ApplicationSelector
                  objects={ruleObjects}
                  selectedIds={applicationObjectIds}
                  onChange={setApplicationObjectIds}
                  disabled={busy}
                />
              </SimpleGrid>
            </>
          )}
          {error && (
            <Alert
              color={prepared?.approval_required ? 'yellow' : 'red'}
              title={
                prepared?.approval_required ? 'Approval required' : 'Rule update could not continue'
              }
              role="alert"
            >
              {error}
            </Alert>
          )}
          {busy && !prepared && !queued && (
            <Alert color="blue" title="Checking and saving rule changes">
              Validating permissions and provider values, then submitting the Changeset.
            </Alert>
          )}
          {prepared && !queued && (
            <AppCard className="fm-subtle-panel">
              <Text fw={700}>
                {prepared.approval_required
                  ? 'Changeset submitted'
                  : prepared.state === 'READY'
                    ? 'Ready to update'
                    : 'Preflight result'}
              </Text>
              <Text size="sm" mt={5}>
                {prepared.title}
              </Text>
              <AppStatusBadge
                value={prepared.approval_required ? 'PENDING' : prepared.state}
                label={prepared.approval_required ? 'AWAITING APPROVAL' : undefined}
              />
            </AppCard>
          )}
          {queued && (
            <Alert color="blue" title="Rule update queued">
              Changeset {queued.title} is visible on the Changesets page with its execution status.
            </Alert>
          )}
          <Group justify="flex-end">
            {prepared &&
              !queued &&
              !prepared.approval_required &&
              (prepared.state !== 'READY' || Boolean(error)) && (
                <Button
                  variant="light"
                  onClick={() => {
                    setPrepared(undefined);
                    setError('');
                    setVerificationStarted(false);
                  }}
                  disabled={busy}
                >
                  Back and edit
                </Button>
              )}
            <Button variant="subtle" onClick={close} disabled={busy}>
              {queued || prepared ? 'Close' : 'Cancel'}
            </Button>
            {!prepared && !queued && (
              <Button
                loading={busy}
                disabled={
                  !name.trim() ||
                  Boolean(
                    ruleScopeError(
                      sourceZoneIds,
                      destinationZoneIds,
                      sourceObjectIds,
                      destinationObjectIds,
                    ),
                  )
                }
                onClick={() => void prepare()}
              >
                Save changes
              </Button>
            )}
          </Group>
        </Stack>
      </Dialog>
      <Dialog
        opened={verificationStarted}
        onClose={close}
        title="Rule change submission"
        centered
        size="lg"
        closeOnClickOutside={!busy}
        closeOnEscape={!busy}
      >
        <Stack gap="md">
          {busy && (
            <Alert color="blue" title="Checking and saving rule changes">
              Validating permissions and provider values, then submitting the Changeset.
            </Alert>
          )}
          {error && (
            <Alert
              color={prepared?.approval_required ? 'yellow' : 'red'}
              title={
                prepared?.approval_required ? 'Approval required' : 'Rule update could not continue'
              }
            >
              {error}
            </Alert>
          )}
          {prepared && (
            <AppCard className="fm-subtle-panel">
              <Text fw={700}>
                {prepared.approval_required
                  ? 'Changeset submitted'
                  : prepared.state === 'READY'
                    ? 'Rule update accepted'
                    : 'Validation failed'}
              </Text>
              <Text size="sm" mt={5}>
                {prepared.title}
              </Text>
              <Group justify="space-between" align="center" mt={5}>
                <Text size="xs" c="dimmed">
                  {context.provider_name} ({context.provider_type.toUpperCase()}) ·{' '}
                  {context.policy.name} · {groupName}
                </Text>
                <AppStatusBadge
                  value={prepared.approval_required ? 'PENDING' : prepared.state}
                  label={prepared.approval_required ? 'AWAITING APPROVAL' : undefined}
                />
              </Group>
            </AppCard>
          )}
          {queued && (
            <Alert color="blue" title="Rule changes submitted">
              Changeset {queued.title} was submitted and will appear on the Changesets page.
            </Alert>
          )}
          <Group justify="flex-end">
            {prepared &&
              !queued &&
              !prepared.approval_required &&
              (prepared.state !== 'READY' || Boolean(error)) && (
                <Button
                  variant="light"
                  onClick={() => {
                    setPrepared(undefined);
                    setError('');
                    setVerificationStarted(false);
                  }}
                  disabled={busy}
                >
                  Back and edit
                </Button>
              )}
            <Button variant="subtle" onClick={close} disabled={busy}>
              Close
            </Button>
          </Group>
        </Stack>
      </Dialog>
    </>
  );
}

function DeleteRuleDialog({
  rule,
  onClose,
  onConfirm,
}: {
  rule: DelegatedContext['rules'][number] | undefined;
  onClose: () => void;
  onConfirm: (rule: DelegatedContext['rules'][number]) => void;
}) {
  return (
    <Dialog
      opened={Boolean(rule)}
      onClose={onClose}
      title="Delete firewall rule"
      centered
      size="md"
    >
      <Stack gap="md">
        {rule && (
          <Alert color="red" title={`Delete ${rule.name}?`}>
            This queues a reviewed Changeset in the background. Only this Group-owned rule will be
            removed; the Group section and its other rules remain in place. You can queue another
            deletion immediately.
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="subtle" onClick={onClose}>
            Cancel
          </Button>
          <Button color="red" disabled={!rule} onClick={() => rule && onConfirm(rule)}>
            Queue deletion
          </Button>
        </Group>
      </Stack>
    </Dialog>
  );
}

interface PendingRule {
  id: string;
  name: string;
  action: string;
  enabled: boolean;
  logging: 'NONE' | 'BEGIN' | 'END';
  source_zone_ids: string[];
  destination_zone_ids: string[];
  source_object_ids: string[];
  destination_object_ids: string[];
  source_port_object_ids: string[];
  destination_port_object_ids: string[];
  application_object_ids: string[];
  intrusion_policy_id?: string;
  variable_set_id?: string;
  file_policy_id?: string;
  category_id?: string;
  position?: number;
  placement?: 'BEFORE' | 'AFTER';
  anchor_rule_id?: string;
}

function pendingRuleFromOperation(operation: ChangeSet['operations'][number]): PendingRule {
  const payload = operation.payload;
  const strings = (value: unknown) => (Array.isArray(value) ? value.map(String) : []);
  return {
    id: operation.id,
    name: String(payload.name ?? ''),
    action: String(payload.action ?? 'ALLOW'),
    enabled: payload.enabled !== false,
    logging: ['NONE', 'BEGIN', 'END'].includes(String(payload.logging))
      ? (String(payload.logging) as PendingRule['logging'])
      : 'NONE',
    source_zone_ids: strings(payload.source_zone_ids),
    destination_zone_ids: strings(payload.destination_zone_ids),
    source_object_ids: strings(payload.source_object_ids),
    destination_object_ids: strings(payload.destination_object_ids),
    source_port_object_ids: strings(payload.source_port_object_ids),
    destination_port_object_ids: strings(payload.destination_port_object_ids),
    application_object_ids: strings(payload.application_object_ids),
    intrusion_policy_id: payload.intrusion_policy_id
      ? String(payload.intrusion_policy_id)
      : undefined,
    variable_set_id: payload.variable_set_id ? String(payload.variable_set_id) : undefined,
    file_policy_id: payload.file_policy_id ? String(payload.file_policy_id) : undefined,
    category_id: payload.category_id ? String(payload.category_id) : undefined,
  };
}

function rulePlacementOptions(rules: DelegatedContext['rules']) {
  const last = rules.at(-1);
  if (!last) return [];
  return [
    ...rules.map((rule) => ({ value: `BEFORE:${rule.id}`, label: `Before ${rule.name}` })),
    {
      value: `AFTER:${last.id}`,
      label: `After ${last.name} (end of section)`,
    },
  ];
}

function defaultRulePlacement(rules: DelegatedContext['rules']) {
  const last = rules.at(-1);
  return last ? `AFTER:${last.id}` : 'DEFAULT';
}

function rulePlacementPayload(
  value: string | null,
  existing: DelegatedContext['rules'],
): Pick<PendingRule, 'placement' | 'position' | 'anchor_rule_id'> | Record<string, never> {
  if (!value || value === 'DEFAULT') return {};
  const [placement, anchorRuleId] = value.split(':');
  if ((placement !== 'BEFORE' && placement !== 'AFTER') || !anchorRuleId) return {};
  const anchor = existing.find((rule) => rule.id === anchorRuleId);
  return { placement, position: anchor?.position, anchor_rule_id: anchorRuleId };
}

function rulePlacementValue(rule: PendingRule) {
  return rule.placement && rule.position !== undefined
    ? `${rule.placement}:${rule.anchor_rule_id}`
    : 'DEFAULT';
}

function rulePlacementLabel(rule: PendingRule, existing: DelegatedContext['rules']) {
  if (!rule.placement || rule.position === undefined) return 'Only rule in section';
  const anchor = existing.find((item) => item.id === rule.anchor_rule_id);
  return `${rule.placement === 'AFTER' ? 'After' : 'Before'} ${anchor?.name ?? `position ${rule.position}`}`;
}

function selectOption(item: { id: string; name: string }) {
  return { value: item.id, label: item.name };
}

function ApplicationSelector({
  objects,
  selectedIds,
  onChange,
  disabled,
}: {
  objects: DelegatedContext['objects'];
  selectedIds: string[];
  onChange: (values: string[]) => void;
  disabled?: boolean;
}) {
  const [filterQuery, setFilterQuery] = useState('');
  const [applicationQuery, setApplicationQuery] = useState('');
  const [scopedFilterIds, setScopedFilterIds] = useState<Set<string>>(new Set());
  const [openFilterGroups, setOpenFilterGroups] = useState<Set<string>>(() => new Set(['risk']));
  const filters = objects.filter((object) => object.object_type === 'APPLICATION_FILTER');
  const applications = objects.filter((object) => object.object_type === 'APPLICATION');
  const selectedFilterIds = new Set(
    selectedIds.filter((id) => filters.some((filter) => filter.id === id)),
  );
  const selectedApplicationIds = new Set(
    selectedIds.filter((id) => applications.some((application) => application.id === id)),
  );
  const [checkedFilterIds, setCheckedFilterIds] = useState<Set<string>>(() => new Set());
  const [checkedApplicationIds, setCheckedApplicationIds] = useState<Set<string>>(() => new Set());
  const filterSearch = filterQuery.trim().toLowerCase();
  const applicationSearch = applicationQuery.trim().toLowerCase();
  const visibleFilters = filters.filter(
    (filter) => !filterSearch || filter.name.toLowerCase().includes(filterSearch),
  );
  const filterGroups = [
    { id: 'user', label: 'User-Created Filters' },
    { id: 'risk', label: 'Risks' },
    { id: 'productivity', label: 'Business Relevance' },
    { id: 'type', label: 'Types' },
    { id: 'category', label: 'Categories' },
    { id: 'tag', label: 'Tags' },
  ]
    .map((group) => ({
      ...group,
      filters: visibleFilters.filter((filter) => {
        const criterion = String(
          parseJsonRecord(filter.normalized_value)?.criterion ?? '',
        ).toLowerCase();
        return group.id === 'user'
          ? !['risk', 'productivity', 'type', 'category', 'tag'].includes(criterion)
          : criterion === group.id;
      }),
    }))
    .filter((group) => group.filters.length > 0);
  const filterLabel = (filter: (typeof filters)[number]) => {
    const value = parseJsonRecord(filter.normalized_value);
    const count = typeof value?.count === 'number' ? value.count : undefined;
    return count === undefined ? filter.name : `${filter.name} (${count})`;
  };
  const scopedApplications = scopedFilterIds.size
    ? applications.filter(
        (application) =>
          selectedApplicationIds.has(application.id) ||
          [...scopedFilterIds].some((filterId) => {
            const filter = filters.find((item) => item.id === filterId);
            return filter ? applicationMatchesFilter(application, filter) : false;
          }),
      )
    : applications;
  const visibleApplications = scopedApplications.filter(
    (application) =>
      !applicationSearch ||
      application.name.toLowerCase().includes(applicationSearch) ||
      String(application.normalized_value ?? '')
        .toLowerCase()
        .includes(applicationSearch),
  );
  const matchingMetadataAvailable = applications.some((application) =>
    Boolean(application.provider_metadata?.application_attributes),
  );
  const applicationDescription = scopedFilterIds.size
    ? matchingMetadataAvailable
      ? 'Select individual applications from the scoped filter, or use the filter itself in the rule.'
      : 'This provider catalog does not include application-to-filter membership; showing the searchable application catalog.'
    : 'Select individual applications, or select a filter above to scope this list.';

  return (
    <div className="fm-application-selector">
      <div className="fm-application-pane">
        <Text size="sm" fw={600}>
          Application filters
        </Text>
        <Text size="xs" c="dimmed">
          Select a filter for the rule, or use it to narrow the applications on the right.
        </Text>
        <TextInput
          mt="sm"
          placeholder="Search filter names"
          value={filterQuery}
          onChange={(event) => setFilterQuery(event.currentTarget.value)}
          disabled={disabled}
        />
        <div className="fm-application-options">
          {filterGroups.map((group) => {
            const open = openFilterGroups.has(group.id) || Boolean(filterSearch);
            return (
              <div key={group.id} className="fm-filter-group">
                <button
                  type="button"
                  className="fm-filter-group-header"
                  onClick={() => {
                    const next = new Set(openFilterGroups);
                    if (next.has(group.id)) next.delete(group.id);
                    else next.add(group.id);
                    setOpenFilterGroups(next);
                  }}
                  aria-expanded={open}
                >
                  {open ? <IconChevronDown size={17} /> : <IconChevronRight size={17} />}
                  <span>{group.label}</span>
                </button>
                {open &&
                  group.filters.map((filter) => (
                    <Checkbox
                      key={filter.id}
                      className="fm-filter-group-item"
                      label={filterLabel(filter)}
                      checked={checkedFilterIds.has(filter.id)}
                      onChange={(event) => {
                        const nextFilters = new Set(checkedFilterIds);
                        const nextScopes = new Set(scopedFilterIds);
                        if (event.currentTarget.checked) {
                          nextFilters.add(filter.id);
                          nextScopes.add(filter.id);
                        } else {
                          nextFilters.delete(filter.id);
                          nextScopes.delete(filter.id);
                        }
                        setCheckedFilterIds(nextFilters);
                        setScopedFilterIds(nextScopes);
                      }}
                      disabled={disabled}
                    />
                  ))}
              </div>
            );
          })}
          {!filterGroups.length && (
            <Text size="sm" c="dimmed">
              No filters found.
            </Text>
          )}
        </div>
        <div className="fm-application-add-action">
          <Button
            fullWidth
            variant="light"
            onClick={() => {
              const nextIds = new Set(selectedIds);
              checkedFilterIds.forEach((id) => nextIds.add(id));
              onChange([...nextIds]);
              setCheckedFilterIds(new Set());
              setCheckedApplicationIds(new Set());
              setScopedFilterIds(new Set());
            }}
            disabled={disabled || checkedFilterIds.size === 0}
          >
            Add selected filter{checkedFilterIds.size === 1 ? '' : 's'}
          </Button>
        </div>
      </div>
      <div className="fm-application-pane">
        <Text size="sm" fw={600}>
          Applications
        </Text>
        <Text size="xs" c="dimmed">
          {applicationDescription}
        </Text>
        <TextInput
          mt="sm"
          placeholder="Search application objects"
          value={applicationQuery}
          onChange={(event) => setApplicationQuery(event.currentTarget.value)}
          disabled={disabled}
        />
        <div className="fm-application-options">
          {visibleApplications.slice(0, 250).map((application) => (
            <Checkbox
              key={application.id}
              label={application.name}
              checked={checkedApplicationIds.has(application.id)}
              onChange={(event) => {
                const nextApplications = new Set(checkedApplicationIds);
                if (event.currentTarget.checked) nextApplications.add(application.id);
                else nextApplications.delete(application.id);
                setCheckedApplicationIds(nextApplications);
              }}
              disabled={disabled}
            />
          ))}
          {!visibleApplications.length && (
            <Text size="sm" c="dimmed">
              No applications found.
            </Text>
          )}
          {visibleApplications.length > 250 && (
            <Text size="xs" c="dimmed">
              Showing the first 250 results. Use search to narrow the list.
            </Text>
          )}
        </div>
        <div className="fm-application-add-action">
          <Button
            fullWidth
            variant="light"
            onClick={() => {
              const nextIds = new Set(selectedIds);
              checkedApplicationIds.forEach((id) => nextIds.add(id));
              onChange([...nextIds]);
              setCheckedFilterIds(new Set());
              setCheckedApplicationIds(new Set());
              setScopedFilterIds(new Set());
            }}
            disabled={disabled || checkedApplicationIds.size === 0}
          >
            Add selected application{checkedApplicationIds.size === 1 ? '' : 's'}
          </Button>
        </div>
      </div>
      <div className="fm-application-selection-summary">
        <Text size="sm" fw={600}>
          Applications and filters to add to this rule
        </Text>
        <Group gap="xs" mt="xs">
          {[...selectedFilterIds, ...selectedApplicationIds].map((id) => {
            const object = objects.find((item) => item.id === id);
            if (!object) return null;
            return (
              <Button
                key={id}
                size="compact-sm"
                variant="default"
                onClick={() => onChange(selectedIds.filter((selectedId) => selectedId !== id))}
                disabled={disabled}
              >
                {object.name} ×
              </Button>
            );
          })}
          {!selectedFilterIds.size && !selectedApplicationIds.size && (
            <Text size="sm" c="dimmed">
              Nothing selected yet.
            </Text>
          )}
        </Group>
      </div>
    </div>
  );
}

function applicationMatchesFilter(
  application: DelegatedContext['objects'][number],
  filter: DelegatedContext['objects'][number],
) {
  const filterValue =
    parseJsonRecord(filter.normalized_value) ?? parseFilterValue(filter.normalized_value);
  const memberships = Array.isArray(filterValue?.applications)
    ? filterValue.applications.filter((item): item is Record<string, unknown> =>
        Boolean(item && typeof item === 'object'),
      )
    : [];
  if (memberships.length) {
    const applicationName = application.name.toLowerCase();
    const applicationId = application.id.toLowerCase();
    const applicationProviderId = String(
      parseJsonRecord(application.provider_metadata?.application_attributes)?.provider_native_id ??
        application.provider_metadata?.provider_native_id ??
        '',
    ).toLowerCase();
    return memberships.some(
      (membership) =>
        String(membership.id ?? '').toLowerCase() === applicationId ||
        (applicationProviderId &&
          String(membership.id ?? '').toLowerCase() === applicationProviderId) ||
        String(membership.name ?? '').toLowerCase() === applicationName,
    );
  }
  const attributes = {
    ...parseJsonRecord(application.provider_metadata?.application_payload),
    ...parseJsonRecord(application.provider_metadata?.application_attributes),
  };
  if (!filterValue || !attributes) return true;
  const criterion = String(filterValue.criterion ?? '').toLowerCase();
  const targets = [filterValue.name, filterValue.id]
    .filter(
      (value): value is string | number => typeof value === 'string' || typeof value === 'number',
    )
    .map((value) => String(value).trim().toLowerCase())
    .filter(Boolean);
  if (!criterion || !targets.length) return true;
  const candidateKeys =
    criterion === 'tag'
      ? ['tags', 'applicationTags', 'appTags']
      : criterion === 'type'
        ? ['applicationTypes', 'applicationType', 'appTypes', 'type']
        : criterion === 'productivity'
          ? ['productivity', 'appProductivity', 'businessRelevance']
          : [criterion, criterion.slice(0, -1)];
  const candidate = candidateKeys
    .map((key) => attributes[key])
    .find((value) => value !== undefined);
  if (Array.isArray(candidate)) {
    return candidate.some((item) => {
      if (item && typeof item === 'object') {
        const record = item as Record<string, unknown>;
        return [record.name, record.id, record.value]
          .filter((value) => value !== undefined && value !== null)
          .some((value) => targets.includes(String(value).toLowerCase()));
      }
      return targets.includes(String(item).toLowerCase());
    });
  }
  if (candidate && typeof candidate === 'object') {
    const record = candidate as Record<string, unknown>;
    return [record.name, record.id, record.value]
      .filter((value) => value !== undefined && value !== null)
      .some((value) => targets.includes(String(value).toLowerCase()));
  }
  return candidate !== undefined && targets.includes(String(candidate).toLowerCase());
}

function parseFilterValue(value?: string | null): Record<string, unknown> | undefined {
  if (!value) return undefined;
  const separator = value.indexOf('=');
  if (separator < 1) return undefined;
  return {
    criterion: value.slice(0, separator).trim(),
    name: value.slice(separator + 1).trim(),
  };
}

function parseJsonRecord(value?: string | null): Record<string, unknown> | undefined {
  if (!value) return undefined;
  try {
    const parsed: unknown = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function ruleElementCount(rule: PendingRule) {
  return (
    rule.source_zone_ids.length +
    rule.destination_zone_ids.length +
    rule.source_object_ids.length +
    rule.destination_object_ids.length +
    rule.source_port_object_ids.length +
    rule.destination_port_object_ids.length +
    rule.application_object_ids.length
  );
}

function defaultRuleChangeSetName(groupName: string) {
  const timestamp = new Date().toISOString().slice(0, 16).replace('T', ' ');
  return `${groupName} rules · ${timestamp} UTC`;
}

function providerRuleName(groupSlug: string, name: string) {
  const prefix = `${groupSlug}__`;
  const requested = name.startsWith(prefix) ? name.slice(prefix.length) : name;
  const component = requested
    .trim()
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^[-._]+|[-._]+$/g, '');
  return `${prefix}${component}`;
}

function editableRuleName(groupSlug: string, providerName: string) {
  const prefix = `${groupSlug}__`;
  return providerName.startsWith(prefix) ? providerName.slice(prefix.length) : providerName;
}

function idsForNames(items: Array<{ id: string; name: string }>, names: string[]) {
  const selected = new Set(names);
  return items.filter((item) => selected.has(item.name)).map((item) => item.id);
}

function rulePreflightError(changeSet: ChangeSet) {
  for (const operation of changeSet.operations) {
    const denied = operation.validation_results.find((result) => result.allowed === false);
    const reason = typeof denied?.reason === 'string' ? denied.reason : '';
    if (reason) return `Preflight denied this rule: ${humanize(reason)}.`;
  }
  return 'Preflight did not approve this rule. Review the Changeset validation details.';
}

function ruleScopeError(
  sourceZoneIds: string[],
  destinationZoneIds: string[],
  sourceObjectIds: string[],
  destinationObjectIds: string[],
) {
  if (!sourceZoneIds.length || !destinationZoneIds.length) {
    return 'Select at least one source zone and one destination zone.';
  }
  if (!sourceObjectIds.length && !destinationObjectIds.length) {
    return 'Specify at least one source or destination network; both sides cannot be Any.';
  }
  return '';
}

function ruleDialogError(reason: unknown) {
  return reason instanceof ApiError
    ? `${reason.message} Reference: ${reason.correlationId}`
    : 'The rule Changeset request failed.';
}

function ObjectsWorkspace({
  context,
  groupName,
  groupSlug,
  activeGroupId,
  activity,
}: {
  context: DelegatedContext;
  groupName: string;
  groupSlug: string;
  activeGroupId: string;
  activity: ChangeSet[];
}) {
  const [query, setQuery] = useState('');
  const [type, setType] = useState<string | null>('ALL');
  const [page, setPage] = useState(1);
  const pageSize = useAdaptivePageSize();
  const [creating, setCreating] = useState(false);
  const [correctionObjects, setCorrectionObjects] = useState<PendingObject[]>([]);
  const [editing, setEditing] = useState<DelegatedContext['objects'][number]>();
  const [deleting, setDeleting] = useState<DelegatedContext['objects'][number]>();
  const recentCutoff = useRecentActivityCutoff();
  const trackedObjectOperations = activity
    .filter(
      (changeSet) =>
        changeSet.access_policy_id === context.policy.id &&
        (['READY', 'QUEUED', 'EXECUTING'].includes(changeSet.state) ||
          (['SUCCEEDED', 'FAILED', 'CONFLICT', 'PARTIALLY_SUCCEEDED'].includes(changeSet.state) &&
            Date.parse(changeSet.updated_at) >= recentCutoff)),
    )
    .flatMap((changeSet) =>
      changeSet.operations
        .filter((operation) =>
          ['CREATE_OBJECT', 'MODIFY_OBJECT', 'DELETE_OBJECT'].includes(operation.kind),
        )
        .map((operation) => ({ changeSet, operation })),
    );
  const rejectedObjectOperations = activity
    .filter(
      (changeSet) =>
        changeSet.access_policy_id === context.policy.id && changeSet.state === 'REJECTED',
    )
    .flatMap((changeSet) =>
      changeSet.operations
        .filter((operation) => operation.kind === 'CREATE_OBJECT')
        .map((operation) => ({
          changeSet,
          object: {
            id: `rejected-${changeSet.id}-${operation.id}`,
            object_type: String(operation.payload.object_type ?? ''),
            name: String(operation.payload.name ?? ''),
            value: String(operation.payload.value ?? ''),
            member_object_ids: Array.isArray(operation.payload.member_object_ids)
              ? operation.payload.member_object_ids.map(String)
              : [],
          },
        })),
    );
  const pendingObjectOperations = activity
    .filter(
      (changeSet) =>
        changeSet.access_policy_id === context.policy.id &&
        changeSet.approval_required &&
        changeSet.state === 'READY',
    )
    .flatMap((changeSet) =>
      changeSet.operations
        .filter((operation) => operation.kind === 'CREATE_OBJECT')
        .map((operation) => ({
          changeSet,
          object: {
            id: `pending-${changeSet.id}-${operation.id}`,
            object_type: String(operation.payload.object_type ?? ''),
            name: String(operation.payload.name ?? ''),
            value: String(operation.payload.value ?? ''),
            member_object_ids: Array.isArray(operation.payload.member_object_ids)
              ? operation.payload.member_object_ids.map(String)
              : [],
          },
        })),
    );
  const synchronizedNames = new Set(context.objects.map((item) => item.name.toLowerCase()));
  const providerSyncObjectOperations = activity
    .filter(
      (changeSet) =>
        changeSet.access_policy_id === context.policy.id &&
        ['QUEUED', 'EXECUTING', 'SUCCEEDED', 'CONFLICT'].includes(changeSet.state) &&
        (['QUEUED', 'EXECUTING', 'CONFLICT'].includes(changeSet.state) ||
          Date.parse(changeSet.updated_at) >= recentCutoff),
    )
    .flatMap((changeSet) =>
      changeSet.operations
        .filter((operation) => operation.kind === 'CREATE_OBJECT')
        .map((operation) => ({
          changeSet,
          object: {
            id: `sync-${changeSet.id}-${operation.id}`,
            object_type: String(operation.payload.object_type ?? ''),
            name: String(operation.payload.name ?? ''),
          },
        })),
    )
    .filter(
      ({ object }) =>
        !synchronizedNames.has(providerObjectNamePreview(groupSlug, object.name).toLowerCase()),
    );
  const latestRejectedObjectOperations = new Map<
    string,
    (typeof rejectedObjectOperations)[number]
  >();
  for (const candidate of rejectedObjectOperations) {
    const key = `${candidate.object.object_type}:${candidate.object.name.toLowerCase()}`;
    const existing = latestRejectedObjectOperations.get(key);
    if (
      !existing ||
      Date.parse(candidate.changeSet.rejected_at ?? candidate.changeSet.updated_at) >=
        Date.parse(existing.changeSet.rejected_at ?? existing.changeSet.updated_at)
    ) {
      latestRejectedObjectOperations.set(key, candidate);
    }
  }
  const deduplicatedRejectedObjectOperations = [...latestRejectedObjectOperations.values()];
  const pendingObjectKeys = new Set(
    pendingObjectOperations.map(
      ({ object }) => `${object.object_type}:${object.name.toLowerCase()}`,
    ),
  );
  const replacementObjectKeys = new Set(
    activity
      .filter(
        (changeSet) =>
          changeSet.access_policy_id === context.policy.id && changeSet.state !== 'REJECTED',
      )
      .flatMap((changeSet) =>
        changeSet.operations
          .filter((operation) => operation.kind === 'CREATE_OBJECT')
          .map(
            (operation) =>
              `${String(operation.payload.object_type ?? '')}:${String(operation.payload.name ?? '').toLowerCase()}`,
          ),
      ),
  );
  const visibleRejectedObjectOperations = deduplicatedRejectedObjectOperations.filter(
    ({ object }) =>
      !pendingObjectKeys.has(`${object.object_type}:${object.name.toLowerCase()}`) &&
      !replacementObjectKeys.has(`${object.object_type}:${object.name.toLowerCase()}`),
  );
  const visibleObjects = context.objects.filter(
    (item) => item.object_type !== 'APPLICATION' && item.object_type !== 'APPLICATION_FILTER',
  );
  const pendingSyncRows = providerSyncObjectOperations.map(({ changeSet, object }) => ({
    id: object.id,
    name: providerObjectNamePreview(groupSlug, object.name),
    object_type: object.object_type,
    pendingSync: true as const,
    syncState: changeSet.state,
    changeSetTitle: changeSet.title,
  }));
  const inventoryRows = [...visibleObjects, ...pendingSyncRows];
  const rows = inventoryRows.filter(
    (item) =>
      item.name.toLowerCase().includes(query.toLowerCase()) &&
      (type === 'ALL' || item.object_type === type),
  );
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pagedRows = rows.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const types = [...new Set(inventoryRows.map((item) => item.object_type))];
  return (
    <AppCard>
      <Group justify="space-between" align="end" mb="md">
        <div>
          <Text className="fm-eyebrow">Authorized inventory</Text>
          <Title order={2} size="h4">
            Objects usable by {groupName}
          </Title>
          <Text size="xs" c="dimmed">
            Objects available to this Group in the active policy. Ownership determines what can be
            managed.
          </Text>
        </div>
        <Button
          leftSection={<IconPlus size={16} />}
          disabled={
            !context.provider_writable ||
            !context.object_create.some((item) => item.provider_supported)
          }
          onClick={() => setCreating(true)}
        >
          Create object
        </Button>
      </Group>
      <CreateObjectDialog
        key={`create-${correctionObjects.map((item) => item.id).join('|') || 'new'}`}
        opened={creating}
        onClose={() => {
          setCreating(false);
          setCorrectionObjects([]);
        }}
        activeGroupId={activeGroupId}
        groupName={groupName}
        groupSlug={groupSlug}
        context={context}
        initialObjects={correctionObjects}
      />
      <ModifyObjectDialog
        key={`modify-${editing?.id ?? 'none'}`}
        opened={Boolean(editing)}
        onClose={() => setEditing(undefined)}
        activeGroupId={activeGroupId}
        groupName={groupName}
        context={context}
        object={editing}
      />
      <DeleteObjectDialog
        key={`delete-${deleting?.id ?? 'none'}`}
        opened={Boolean(deleting)}
        onClose={() => setDeleting(undefined)}
        activeGroupId={activeGroupId}
        groupName={groupName}
        context={context}
        object={deleting}
      />
      <Group mb="md">
        <TextInput
          className="fm-object-search"
          aria-label="Search objects"
          placeholder="Search objects"
          leftSection={<IconSearch size={15} />}
          value={query}
          onChange={(event) => {
            setQuery(event.currentTarget.value);
            setPage(1);
          }}
        />
        <Select
          aria-label="Filter object type"
          value={type}
          onChange={(value) => {
            setType(value);
            setPage(1);
          }}
          data={[
            { value: 'ALL', label: 'All object types' },
            ...types.map((value) => ({ value, label: humanize(value) })),
          ]}
        />
      </Group>
      {visibleRejectedObjectOperations.length > 0 && (
        <AppCard className="fm-subtle-panel" mb="md">
          <Group justify="space-between" align="end" mb="sm">
            <div>
              <Text fw={700}>Rejected objects</Text>
              <Text size="sm" c="dimmed">
                These objects were not created on the provider. Correct the complete request and
                resubmit it together.
              </Text>
            </div>
            <ActionButton
              intent="secondary"
              onClick={() => {
                setCorrectionObjects(visibleRejectedObjectOperations.map(({ object }) => object));
                setCreating(true);
              }}
            >
              Correct all and resubmit
            </ActionButton>
          </Group>
          <AppDataTable label="Rejected firewall objects">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Object</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Action</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {visibleRejectedObjectOperations.map(({ changeSet, object }) => (
                <Table.Tr key={`${changeSet.id}-${object.id}`}>
                  <Table.Td>
                    <Text fw={650}>{providerObjectNamePreview(groupSlug, object.name)}</Text>
                    <Text size="xs" c="red">
                      Rejected by{' '}
                      {changeSet.rejected_by_display_name ??
                        changeSet.rejected_by_email ??
                        'an approver'}
                      : {changeSet.rejection_reason ?? 'No reason was provided.'}
                    </Text>
                  </Table.Td>
                  <Table.Td>{humanize(object.object_type)}</Table.Td>
                  <Table.Td>
                    <span
                      className="fm-resource-state-notice fm-resource-state-rejected"
                      aria-label="Rejected"
                    >
                      <IconAlertTriangle size={16} stroke={2} />
                      <span>Rejected</span>
                    </span>
                  </Table.Td>
                  <Table.Td>
                    <ActionButton
                      intent="secondary"
                      onClick={() => {
                        setCorrectionObjects([object]);
                        setCreating(true);
                      }}
                    >
                      Correct and resubmit
                    </ActionButton>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </AppDataTable>
        </AppCard>
      )}
      {pendingObjectOperations.length > 0 && (
        <AppCard className="fm-subtle-panel" mb="md">
          <Text fw={700} mb="xs">
            Objects awaiting approval
          </Text>
          <Text size="sm" c="dimmed" mb="sm">
            These corrected objects are in a Changeset awaiting approval and are not available on
            the provider yet.
          </Text>
          <AppDataTable label="Objects awaiting approval">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Object</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Changeset</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {pendingObjectOperations.map(({ changeSet, object }) => (
                <Table.Tr key={`${changeSet.id}-${object.id}`}>
                  <Table.Td>
                    <Text fw={650}>{providerObjectNamePreview(groupSlug, object.name)}</Text>
                  </Table.Td>
                  <Table.Td>{humanize(object.object_type)}</Table.Td>
                  <Table.Td>
                    <AppStatusBadge
                      value={changeSet.state === 'APPROVED' ? 'ASSIGNED' : 'PENDING'}
                      label={
                        changeSet.state === 'APPROVED'
                          ? 'APPROVED · AWAITING EXECUTION'
                          : 'AWAITING APPROVAL'
                      }
                    />
                  </Table.Td>
                  <Table.Td>{changeSet.title}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </AppDataTable>
        </AppCard>
      )}
      {rows.length === 0 ? (
        <AppEmptyState
          title="No objects found"
          description="No authorized objects match the current filters."
        />
      ) : (
        <AppDataTable label="Authorized firewall objects">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Object</Table.Th>
              <Table.Th>Type</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Ownership</Table.Th>
              <Table.Th>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {pagedRows.map((object) => {
              if ('pendingSync' in object) {
                return (
                  <Table.Tr key={object.id}>
                    <Table.Td>
                      <Text fw={650}>{object.name}</Text>
                    </Table.Td>
                    <Table.Td>{humanize(object.object_type)}</Table.Td>
                    <Table.Td>
                      <AppStatusBadge
                        value={
                          object.syncState === 'EXECUTING'
                            ? 'PENDING'
                            : object.syncState === 'CONFLICT'
                              ? 'CONFLICT'
                              : 'WARNING'
                        }
                        label={
                          object.syncState === 'EXECUTING'
                            ? 'Sync in progress'
                            : object.syncState === 'CONFLICT'
                              ? 'Sync conflict'
                              : 'Sync pending'
                        }
                      />
                    </Table.Td>
                    <Table.Td>
                      <AppStatusBadge value="OWNED" label="Owned" />
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" c="dimmed">
                        {object.changeSetTitle}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                );
              }
              const owned = object.owner_group_id === activeGroupId;
              const usedInRule = objectReferencedByRule(object.name, context.rules);
              const objectChange = trackedObjectOperations.find(
                ({ operation }) => operation.payload.object_id === object.id,
              );
              const objectDeletePending = activity.some(
                (changeSet) =>
                  changeSet.access_policy_id === context.policy.id &&
                  !['SUCCEEDED', 'CANCELLED', 'REJECTED', 'ROLLED_BACK'].includes(
                    changeSet.state,
                  ) &&
                  changeSet.operations.some(
                    (operation) =>
                      operation.kind === 'DELETE_OBJECT' &&
                      operation.payload.object_id === object.id,
                  ),
              );
              const canModify = owned && context.capabilities.includes('modify_object');
              const canDelete = owned && context.capabilities.includes('delete_object');
              return (
                <Table.Tr key={object.id}>
                  <Table.Td>
                    <Text fw={650}>{object.name}</Text>
                  </Table.Td>
                  <Table.Td>{humanize(object.object_type)}</Table.Td>
                  <Table.Td>
                    {objectChange ? (
                      <AppStatusBadge
                        value={objectChange.changeSet.state}
                        label={objectChangeStatusLabel(
                          objectChange.changeSet,
                          objectChange.operation,
                        )}
                      />
                    ) : !usedInRule && object.management_state === 'MANAGED' ? (
                      <AppStatusBadge value="SYNCED" label="In sync" />
                    ) : (
                      <ResourceStateNotice
                        state={object.management_state}
                        firewallState={usedInRule ? object.firewall_state : undefined}
                        deploymentStatus={
                          usedInRule ? context.firewall_deployment_status : undefined
                        }
                        pending={false}
                      />
                    )}
                  </Table.Td>
                  <Table.Td>
                    <AppStatusBadge
                      value={owned ? 'OWNED' : 'SHARED'}
                      label={owned ? 'Owned' : 'Shared'}
                    />
                  </Table.Td>
                  <Table.Td>
                    <Group className="fm-object-row-actions" gap="xs" wrap="wrap">
                      {canModify && (
                        <ActionButton
                          intent="secondary"
                          onClick={() => setEditing(object)}
                          aria-label={`Modify ${object.name}`}
                        >
                          Modify
                        </ActionButton>
                      )}
                      {canDelete && (
                        <ActionButton
                          intent="danger"
                          disabled={usedInRule || objectDeletePending}
                          title={
                            usedInRule
                              ? 'Cannot delete: this object is used by a policy rule.'
                              : objectDeletePending
                                ? 'Deletion is already pending for this object.'
                                : 'Delete object'
                          }
                          onClick={() => setDeleting(object)}
                          aria-label={`Delete ${object.name}`}
                        >
                          Delete
                        </ActionButton>
                      )}
                      {!canModify && !canDelete && (
                        <Text size="xs" c="dimmed">
                          No actions available
                        </Text>
                      )}
                    </Group>
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </AppDataTable>
      )}
      <AdaptivePagination
        page={currentPage}
        pageSize={pageSize}
        total={rows.length}
        onPageChange={setPage}
      />
    </AppCard>
  );
}

function objectChangeStatusLabel(changeSet: ChangeSet, operation: ChangeSet['operations'][number]) {
  const action =
    operation.kind === 'CREATE_OBJECT'
      ? 'Create'
      : operation.kind === 'DELETE_OBJECT'
        ? 'Delete'
        : 'Update';
  const status =
    changeSet.state === 'READY'
      ? 'Ready'
      : changeSet.state === 'QUEUED'
        ? 'Queued'
        : changeSet.state === 'EXECUTING'
          ? 'In progress'
          : humanize(changeSet.state);
  return `${action} · ${status}`;
}

function objectReferencedByRule(objectName: string, rules: DelegatedContext['rules']) {
  return rules.some((rule) =>
    Object.values(rule).some(
      (value) => Array.isArray(value) && value.some((item) => item === objectName),
    ),
  );
}

function CreateObjectDialog({
  opened,
  onClose,
  activeGroupId,
  groupName,
  groupSlug,
  context,
  initialObjects,
}: {
  opened: boolean;
  onClose: () => void;
  activeGroupId: string;
  groupName: string;
  groupSlug: string;
  context: DelegatedContext;
  initialObjects?: PendingObject[];
}) {
  const options = context.object_create
    .filter((item) => item.provider_supported)
    .map((item) => ({ value: item.object_type, label: humanize(item.object_type) }));
  const [objectType, setObjectType] = useState(options[0]?.value ?? '');
  const effectiveObjectType = objectType || options[0]?.value || '';
  const [portProtocol, setPortProtocol] = useState<PortProtocol>('TCP');
  const [icmpType, setIcmpType] = useState('ANY');
  const [icmpCode, setIcmpCode] = useState('ANY');
  const [otherProtocol, setOtherProtocol] = useState('GRE');
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [memberObjectIds, setMemberObjectIds] = useState<string[]>([]);
  const [changeSetName, setChangeSetName] = useState(() => defaultObjectChangeSetName(groupName));
  const [objects, setObjects] = useState<PendingObject[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [prepared, setPrepared] = useState<ChangeSet>();
  const [queued, setQueued] = useState<ChangeSet>();

  useEffect(() => {
    if (!opened || !initialObjects?.length) return;
    const first = initialObjects[0];
    if (!first) return;
    setObjectType(first.object_type);
    setName(first.name);
    setValue(first.value);
    setMemberObjectIds(first.member_object_ids ?? []);
    setObjects(initialObjects);
    setError('');
  }, [opened, initialObjects]);

  const resetAndClose = () => {
    if (busy) return;
    setObjectType(options[0]?.value ?? '');
    setPortProtocol('TCP');
    setIcmpType('ANY');
    setIcmpCode('ANY');
    setOtherProtocol('GRE');
    setName('');
    setValue('');
    setMemberObjectIds([]);
    setChangeSetName(defaultObjectChangeSetName(groupName));
    setObjects([]);
    setError('');
    setPrepared(undefined);
    setQueued(undefined);
    onClose();
  };
  const addObject = () => {
    const cleanName = name.trim();
    const enteredValue = value.trim();
    const isGroup = effectiveObjectType.endsWith('_GROUP');
    const portValue = portValueForForm(portProtocol, value, icmpType, icmpCode, otherProtocol);
    if (
      !effectiveObjectType ||
      !cleanName ||
      (!isGroup && !portValue && effectiveObjectType === 'PORT_SERVICE') ||
      (!isGroup && effectiveObjectType !== 'PORT_SERVICE' && !enteredValue) ||
      (isGroup && !memberObjectIds.length)
    )
      return;
    const cleanValue = effectiveObjectType === 'PORT_SERVICE' ? portValue : enteredValue;
    if (objects.some((item) => item.name.toLocaleLowerCase() === cleanName.toLocaleLowerCase())) {
      setError('Each object in this Changeset must have a unique name.');
      return;
    }
    const valueError = pendingObjectValueError(effectiveObjectType, cleanValue);
    if (valueError) {
      setError(valueError);
      return;
    }
    setError('');
    setObjects((current) => [
      ...current,
      {
        id: `${Date.now()}-${current.length}`,
        object_type: effectiveObjectType,
        name: cleanName,
        value: cleanValue,
        member_object_ids: memberObjectIds,
      },
    ]);
    setName('');
    setValue('');
    setMemberObjectIds([]);
  };
  const editObject = (object: PendingObject) => {
    setObjectType(object.object_type);
    setName(object.name);
    if (object.object_type === 'PORT_SERVICE') {
      const [protocol, first, second] = object.value.split('/');
      if (protocol === 'tcp' || protocol === 'udp') {
        setPortProtocol(protocol.toUpperCase() as PortProtocol);
        setValue(first || '');
      } else if (protocol === 'icmp' || protocol === 'ipv6-icmp') {
        setPortProtocol(protocol === 'icmp' ? 'ICMP' : 'IPV6_ICMP');
        setIcmpType(first || 'ANY');
        setIcmpCode(second || 'ANY');
        setValue('');
      } else {
        setPortProtocol('OTHER');
        setOtherProtocol(first || 'GRE');
        setValue('');
      }
    } else {
      setValue(object.value);
    }
    setMemberObjectIds(object.member_object_ids ?? []);
    setObjects((current) => current.filter((item) => item.id !== object.id));
    setError('');
  };
  const prepare = async () => {
    setBusy(true);
    setError('');
    try {
      const draft = await createChangeSet(
        activeGroupId,
        context.policy.id,
        changeSetName.trim(),
        `Create ${objects.length} object${objects.length === 1 ? '' : 's'} from the Objects workspace.`,
      );
      let withObjects = draft;
      for (const object of objects) {
        withObjects = await addDraftObject(draft.id, activeGroupId, {
          name: object.name,
          object_type: object.object_type,
          value: object.value,
          member_object_ids: object.member_object_ids,
        });
      }
      const validated = await changeSetAction(withObjects.id, activeGroupId, 'preflight');
      setPrepared(validated);
      if (validated.state !== 'READY') {
        setError(objectPreflightError(validated, groupName));
        return;
      }
      if (validated.approval_required) {
        setError(
          'This Group requires approval before object changes can be submitted. Close this dialog and have an authorized approver approve the Changeset.',
        );
        return;
      }
      setQueued(await changeSetAction(validated.id, activeGroupId, 'execute'));
    } catch (reason) {
      const message = dialogError(reason);
      setError(
        /not in a state that permits/i.test(message)
          ? `The Changeset could not be submitted because its state changed before execution. Return to edit the objects or close this attempt. ${message}`
          : message,
      );
    } finally {
      setBusy(false);
    }
  };
  const returnToBasket = () => {
    setPrepared(undefined);
    setError('');
  };

  return (
    <Dialog
      opened={opened}
      onClose={resetAndClose}
      title="Create firewall object"
      centered
      size="lg"
      classNames={{ content: 'fm-object-dialog', body: 'fm-object-dialog-body' }}
      closeOnClickOutside={!busy}
      closeOnEscape={!busy}
    >
      <Stack gap="md">
        {!prepared && !queued && (
          <>
            <Text size="sm" c="dimmed">
              Add one or more objects for {groupName} and {context.policy.name}. One Changeset is
              created and preflighted without leaving this page.
            </Text>
            <TextInput
              label="Changeset name"
              value={changeSetName}
              onChange={(event) => setChangeSetName(event.currentTarget.value)}
              disabled={busy}
            />
            <Select
              key={options.map((option) => option.value).join('|')}
              label="Object type"
              data={options}
              value={effectiveObjectType || null}
              onChange={(next) => {
                setObjectType(next ?? '');
                setValue('');
                setMemberObjectIds([]);
                setError('');
              }}
              disabled={busy}
            />
            <TextInput
              label="Object name"
              description={
                name.trim()
                  ? `Provider name: ${providerObjectNamePreview(groupSlug, name)}`
                  : `The provider name will start with ${groupSlug}__`
              }
              value={name}
              onChange={(event) => setName(event.currentTarget.value)}
              disabled={busy}
            />
            {effectiveObjectType.endsWith('_GROUP') && (
              <MultiSelect
                label="Group members"
                description="Only objects this group can use are listed. Network groups may mix IPv4 and IPv6; port groups must use one protocol."
                data={groupMemberOptions(context.objects, effectiveObjectType)}
                value={memberObjectIds}
                onChange={setMemberObjectIds}
                searchable
                nothingFoundMessage="No authorized compatible objects"
                disabled={busy}
              />
            )}
            {effectiveObjectType === 'PORT_SERVICE' && (
              <>
                <Select
                  label="Protocol"
                  description="TCP and UDP use ports. ICMP and IPv6-ICMP use message type and code. Other protocols do not use a port value."
                  data={portProtocolOptions}
                  value={portProtocol}
                  onChange={(next) => setPortProtocol((next as PortProtocol) || 'TCP')}
                  disabled={busy}
                />
                {(portProtocol === 'ICMP' || portProtocol === 'IPV6_ICMP') && (
                  <Group grow>
                    <Select
                      label="ICMP type"
                      data={portProtocol === 'ICMP' ? icmp4TypeOptions : icmp6TypeOptions}
                      value={icmpType}
                      onChange={(next) => setIcmpType(next || 'ANY')}
                      disabled={busy}
                    />
                    <Select
                      label="ICMP code"
                      data={portProtocol === 'ICMP' ? icmp4CodeOptions : icmp6CodeOptions}
                      value={icmpCode}
                      onChange={(next) => setIcmpCode(next || 'ANY')}
                      disabled={busy}
                    />
                  </Group>
                )}
                {portProtocol === 'OTHER' && (
                  <Select
                    label="Protocol"
                    description="Select an IP protocol supported by the provider."
                    data={otherProtocolOptions}
                    value={otherProtocol}
                    onChange={(next) => setOtherProtocol(next || 'GRE')}
                    disabled={busy}
                  />
                )}
              </>
            )}
            {!effectiveObjectType.endsWith('_GROUP') && (
              <TextInput
                label={effectiveObjectType === 'PORT_SERVICE' ? 'Port' : 'Value'}
                description={objectValueHelp(effectiveObjectType)}
                value={value}
                onChange={(event) => setValue(event.currentTarget.value)}
                disabled={
                  busy ||
                  (effectiveObjectType === 'PORT_SERVICE' && !['TCP', 'UDP'].includes(portProtocol))
                }
              />
            )}
            <Button
              variant="light"
              disabled={
                !effectiveObjectType ||
                !name.trim() ||
                busy ||
                (effectiveObjectType.endsWith('_GROUP')
                  ? !memberObjectIds.length
                  : effectiveObjectType === 'PORT_SERVICE'
                    ? !portValueForForm(portProtocol, value, icmpType, icmpCode, otherProtocol)
                    : !value.trim())
              }
              onClick={addObject}
            >
              Add object to Changeset
            </Button>
            {objects.length > 0 && (
              <div className="fm-object-basket">
                <AppDataTable label="Objects in this Changeset">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th style={{ width: '22%' }}>Object</Table.Th>
                      <Table.Th style={{ width: '23%' }}>Type</Table.Th>
                      <Table.Th>Value</Table.Th>
                      <Table.Th className="fm-object-actions">Actions</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {objects.map((object) => (
                      <Table.Tr key={object.id}>
                        <Table.Td>{object.name}</Table.Td>
                        <Table.Td>{humanize(object.object_type)}</Table.Td>
                        <Table.Td className="fm-object-value">{object.value}</Table.Td>
                        <Table.Td className="fm-object-actions">
                          <Group gap={4} wrap="wrap">
                            <Button
                              size="xs"
                              variant="subtle"
                              px={6}
                              aria-label={`Edit ${object.name}`}
                              onClick={() => editObject(object)}
                            >
                              Edit
                            </Button>
                            <Button
                              size="xs"
                              variant="subtle"
                              px={6}
                              aria-label={`Remove ${object.name}`}
                              onClick={() =>
                                setObjects((current) =>
                                  current.filter((item) => item.id !== object.id),
                                )
                              }
                            >
                              Remove
                            </Button>
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </AppDataTable>
              </div>
            )}
          </>
        )}
        {error && (
          <Alert
            color={prepared?.approval_required ? 'yellow' : 'red'}
            title={
              prepared?.approval_required
                ? 'Approval required'
                : /conflict|already exists/i.test(error)
                  ? 'Object conflict'
                  : 'Object creation could not continue'
            }
            role="alert"
          >
            {error}
          </Alert>
        )}
        {busy && !prepared && !queued && (
          <Alert color="blue" title="Checking and saving objects">
            Validating permissions and provider values, then submitting the Changeset.
          </Alert>
        )}
        {prepared && !queued && (
          <AppCard className="fm-subtle-panel">
            <Text fw={700}>
              {prepared.approval_required
                ? 'Changeset submitted'
                : prepared.state === 'READY'
                  ? 'Ready to create'
                  : 'Preflight result'}
            </Text>
            <Text size="sm" mt={5}>
              {prepared.title} · {prepared.operations.length} object operation
              {prepared.operations.length === 1 ? '' : 's'}
            </Text>
            <Group justify="space-between" align="center" mt={5}>
              <Text size="xs" c="dimmed">
                {context.provider_name} ({context.provider_type.toUpperCase()}) ·{' '}
                {context.policy.name} · {groupName}
              </Text>
              <AppStatusBadge
                value={prepared.approval_required ? 'PENDING' : prepared.state}
                label={prepared.approval_required ? 'AWAITING APPROVAL' : undefined}
              />
            </Group>
          </AppCard>
        )}
        {queued && (
          <Alert color="blue" title="Object creation queued">
            Changeset {queued.title} is queued against {context.provider_name}. Provider deployment
            is not started and may later include pending changes outside this Changeset. The
            reconciled object will appear after execution completes.
          </Alert>
        )}
        <Group justify="flex-end">
          {prepared &&
            !queued &&
            !prepared.approval_required &&
            (prepared.state !== 'READY' || Boolean(error)) && (
              <Button variant="light" onClick={returnToBasket} disabled={busy}>
                Back and edit objects
              </Button>
            )}
          <Button variant="subtle" onClick={resetAndClose} disabled={busy}>
            {queued || prepared ? 'Close' : 'Cancel'}
          </Button>
          {!prepared && !queued && (
            <Button
              loading={busy}
              disabled={!changeSetName.trim() || objects.length === 0}
              onClick={() => void prepare()}
            >
              Save {objects.length} object{objects.length === 1 ? '' : 's'}
            </Button>
          )}
        </Group>
      </Stack>
    </Dialog>
  );
}

function ModifyObjectDialog({
  opened,
  onClose,
  activeGroupId,
  groupName,
  context,
  object,
}: {
  opened: boolean;
  onClose: () => void;
  activeGroupId: string;
  groupName: string;
  context: DelegatedContext;
  object?: DelegatedContext['objects'][number];
}) {
  const [value, setValue] = useState(object?.normalized_value ?? '');
  const [changeSetName, setChangeSetName] = useState(() =>
    object
      ? `Update ${object.name} · ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`
      : '',
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [queued, setQueued] = useState<ChangeSet>();
  const valueChanged = Boolean(
    object && value.trim() && value.trim() !== (object.normalized_value ?? '').trim(),
  );

  const resetAndClose = () => {
    if (busy) return;
    setError('');
    setQueued(undefined);
    onClose();
  };
  const save = async () => {
    if (!object || !valueChanged) return;
    setBusy(true);
    setError('');
    try {
      const draft = await createChangeSet(
        activeGroupId,
        context.policy.id,
        changeSetName.trim(),
        `Modify ${object.name} from the Objects workspace for ${groupName}.`,
      );
      const withObject = await addDraftObject(
        draft.id,
        activeGroupId,
        {
          object_id: object.id,
          object_type: object.object_type,
          name: object.name,
          value: value.trim(),
        },
        'MODIFY_OBJECT',
      );
      const validated = await changeSetAction(withObject.id, activeGroupId, 'preflight');
      if (validated.state !== 'READY') {
        setError(objectPreflightError(validated, groupName));
        return;
      }
      setQueued(await changeSetAction(validated.id, activeGroupId, 'execute'));
    } catch (reason) {
      setError(dialogError(reason));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      opened={opened}
      onClose={resetAndClose}
      title="Modify firewall object"
      centered
      size="lg"
      closeOnClickOutside={!busy}
      closeOnEscape={!busy}
    >
      <Stack gap="md">
        {!queued && (
          <>
            <Text size="sm" c="dimmed">
              Save an object change for {groupName}. The update is checked and submitted through a
              Changeset in one step.
            </Text>
            <TextInput
              label="Changeset name"
              value={changeSetName}
              onChange={(event) => setChangeSetName(event.currentTarget.value)}
              disabled={busy}
            />
            <TextInput
              label="Value"
              description={object ? objectValueHelp(object.object_type) : undefined}
              value={value}
              onChange={(event) => setValue(event.currentTarget.value)}
              disabled={busy}
            />
          </>
        )}
        {error && (
          <Alert color="red" title="Object modification could not continue" role="alert">
            {error}
          </Alert>
        )}
        {busy && !queued && (
          <Alert color="blue" title="Checking and saving modification">
            Validating permissions and provider values, then submitting the Changeset.
          </Alert>
        )}
        {queued && (
          <Alert color="blue" title="Object modification queued">
            Changeset {queued.title} is queued against {context.provider_name}. After the provider
            update completes, the connection will schedule a separate firewall deployment. The
            object will show Deployment pending until the firewall confirms the change.
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="subtle" onClick={resetAndClose} disabled={busy}>
            {queued ? 'Close' : 'Cancel'}
          </Button>
          {!queued && (
            <Button
              loading={busy}
              disabled={!changeSetName.trim() || !valueChanged}
              onClick={() => void save()}
            >
              Save modification
            </Button>
          )}
        </Group>
      </Stack>
    </Dialog>
  );
}

function DeleteObjectDialog({
  opened,
  onClose,
  activeGroupId,
  groupName,
  context,
  object,
}: {
  opened: boolean;
  onClose: () => void;
  activeGroupId: string;
  groupName: string;
  context: DelegatedContext;
  object?: DelegatedContext['objects'][number];
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [prepared, setPrepared] = useState<ChangeSet>();
  const [queued, setQueued] = useState<ChangeSet>();
  const title = object ? `Delete ${object.name}` : 'Delete firewall object';

  const resetAndClose = () => {
    if (busy) return;
    setError('');
    setPrepared(undefined);
    setQueued(undefined);
    onClose();
  };
  const prepare = async () => {
    if (!object) return;
    setBusy(true);
    setError('');
    try {
      const draft = await createChangeSet(
        activeGroupId,
        context.policy.id,
        title,
        `Delete ${object.name} from the Objects workspace for ${groupName}.`,
      );
      const withObject = await addDraftObject(
        draft.id,
        activeGroupId,
        { object_id: object.id, object_type: object.object_type },
        'DELETE_OBJECT',
      );
      const validated = await changeSetAction(withObject.id, activeGroupId, 'preflight');
      setPrepared(validated);
      if (validated.state !== 'READY') setError(objectPreflightError(validated, groupName));
    } catch (reason) {
      setError(dialogError(reason));
    } finally {
      setBusy(false);
    }
  };
  const execute = async () => {
    if (!prepared || prepared.state !== 'READY') return;
    setBusy(true);
    setError('');
    try {
      setQueued(await changeSetAction(prepared.id, activeGroupId, 'execute'));
    } catch (reason) {
      setError(dialogError(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog opened={opened} onClose={resetAndClose} title="Delete firewall object" centered>
      <Stack gap="md">
        {!prepared && !queued && (
          <Alert color="red" title="Confirm deletion">
            This queues deletion of <strong>{object?.name}</strong> from {context.provider_name}.
            References must be removed before the provider can accept it.
          </Alert>
        )}
        {error && (
          <Alert color="red" title="Object deletion could not continue" role="alert">
            {error}
          </Alert>
        )}
        {prepared && !queued && (
          <AppCard className="fm-subtle-panel">
            <Text fw={700}>
              {prepared.state === 'READY' ? 'Ready to delete' : 'Preflight result'}
            </Text>
            <AppStatusBadge value={prepared.state} />
          </AppCard>
        )}
        {queued && (
          <Alert color="blue" title="Object deletion queued">
            Changeset {queued.title} is queued against {context.provider_name}.
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="subtle" onClick={resetAndClose} disabled={busy}>
            {queued || prepared ? 'Close' : 'Cancel'}
          </Button>
          {!prepared && !queued && (
            <Button color="red" loading={busy} disabled={busy} onClick={() => void prepare()}>
              Queue deletion
            </Button>
          )}
          {prepared && !queued && (
            <Button
              color="red"
              loading={busy}
              disabled={prepared.state !== 'READY'}
              onClick={() => void execute()}
            >
              Delete object on provider
            </Button>
          )}
        </Group>
      </Stack>
    </Dialog>
  );
}

interface PendingObject {
  id: string;
  object_type: string;
  name: string;
  value: string;
  member_object_ids?: string[];
}

type PortProtocol = 'TCP' | 'UDP' | 'ICMP' | 'IPV6_ICMP' | 'OTHER';

const portProtocolOptions = [
  { value: 'TCP', label: 'TCP' },
  { value: 'UDP', label: 'UDP' },
  { value: 'ICMP', label: 'ICMP (IPv4)' },
  { value: 'IPV6_ICMP', label: 'IPv6-ICMP' },
  { value: 'OTHER', label: 'Other' },
];

const icmp4TypeOptions = [
  ['ANY', 'Any', '—'],
  ['ECHO_REPLY', 'Echo reply', '0'],
  ['DESTINATION_UNREACHABLE', 'Destination unreachable', '3'],
  ['SOURCE_QUENCH', 'Source quench', '4'],
  ['REDIRECT_MESSAGE', 'Redirect message', '5'],
  ['ALTERNATE_HOST_ADDRESS', 'Alternate host address', '6'],
  ['ECHO_REQUEST', 'Echo request', '8'],
  ['ROUTER_ADVERTISEMENT', 'Router advertisement', '9'],
  ['ROUTER_SOLICITATION', 'Router solicitation', '10'],
  ['TIME_EXCEEDED', 'Time exceeded', '11'],
  ['PARAMETER_PROBLEM', 'Parameter problem', '12'],
  ['TIMESTAMP', 'Timestamp', '13'],
  ['TIMESTAMP_REPLY', 'Timestamp reply', '14'],
  ['INFO_REQUEST', 'Information request', '15'],
  ['INFO_REPLY', 'Information reply', '16'],
  ['ADDR_MASK_REQUEST', 'Address mask request', '17'],
  ['ADDR_MASK_REPLY', 'Address mask reply', '18'],
  ['TRACEROUTE', 'Traceroute', '30'],
].map(([value = '', label = '', number = '']) => ({ value, label: `${label} (${number})` }));

const icmp4CodeOptions = [
  ['ANY', 'Any', '—'],
  ['NET_UNREACHABLE', 'Network unreachable', '0'],
  ['HOST_UNREACHABLE', 'Host unreachable', '1'],
  ['PROTOCOL_UNREACHABLE', 'Protocol unreachable', '2'],
  ['PORT_UNREACHABLE', 'Port unreachable', '3'],
  ['FRAGMENTATION_NEEDED', 'Fragmentation needed', '4'],
  ['SOURCE_ROUTE_FAILED', 'Source route failed', '5'],
  ['DEST_NETWORK_UNKNOWN', 'Destination network unknown', '6'],
  ['DEST_HOST_UNKNOWN', 'Destination host unknown', '7'],
  ['COMM_ADMINISTRATIVELY_PROHIBITED', 'Communication administratively prohibited', '13'],
  ['TTL_EXPIRED_TRANSIT', 'TTL expired in transit', '11'],
  ['BAD_LENGTH', 'Bad length', '1'],
].map(([value = '', label = '', number = '']) => ({ value, label: `${label} (${number})` }));

const icmp6TypeOptions = [
  ['ANY', 'Any', '—'],
  ['DESTINATION_UNREACHABLE', 'Destination unreachable', '1'],
  ['PACKET_TOO_BIG', 'Packet too big', '2'],
  ['TIME_EXCEEDED', 'Time exceeded', '3'],
  ['PARAMETER_PROBLEM', 'Parameter problem', '4'],
  ['ECHO_REQUEST', 'Echo request', '128'],
  ['ECHO_REPLY', 'Echo reply', '129'],
  ['MULTICAST_LISTENER_QUERY', 'Multicast listener query', '130'],
  ['MULTICAST_LISTENER_REPORT', 'Multicast listener report', '131'],
  ['MULTICAST_LISTENER_DONE', 'Multicast listener done', '132'],
  ['ROUTER_SOLICITATION', 'Router solicitation', '133'],
  ['ROUTER_ADVERTISEMENT', 'Router advertisement', '134'],
  ['NEIGHBOUR_SOLICITATION', 'Neighbour solicitation', '135'],
  ['NEIGHBOUR_ADVERTISEMENT', 'Neighbour advertisement', '136'],
  ['REDIRECT_MESSAGE', 'Redirect message', '137'],
].map(([value = '', label = '', number = '']) => ({ value, label: `${label} (${number})` }));

const icmp6CodeOptions = [
  ['ANY', 'Any', '—'],
  ['NO_ROUTE_DEST', 'No route to destination', '0'],
  ['COMMUNICATION_PROHIBITED', 'Communication prohibited', '1'],
  ['BEYOND_SCOPE_SRC_ADDR', 'Beyond scope of source address', '2'],
  ['ADDRESS_UNREACHABLE', 'Address unreachable', '3'],
  ['PORT_UNREACHABLE', 'Port unreachable', '4'],
  ['SOURCE_ADDRESS_FAILED', 'Source address failed', '5'],
  ['REJECT_ROUTE', 'Reject route', '6'],
  ['HOP_LIMIT_EXCEEDED', 'Hop limit exceeded', '0'],
  ['FRAGMENT_REASSEMBLY_TIME_EXCEEDED', 'Fragment reassembly time exceeded', '1'],
].map(([value = '', label = '', number = '']) => ({ value, label: `${label} (${number})` }));

const otherProtocolOptions = [
  ['IGMP', 'IGMP', '2'],
  ['GGP', 'GGP', '3'],
  ['ST2', 'ST2', '5'],
  ['CBT', 'CBT', '7'],
  ['EGP', 'EGP', '8'],
  ['IGP', 'IGP', '9'],
  ['PUP', 'PUP', '12'],
  ['XNET', 'XNET', '15'],
  ['CHAOS', 'Chaos', '16'],
  ['MUX', 'MUX', '18'],
  ['DCNMEAS', 'DCN MEAS', '19'],
  ['HMP', 'HMP', '20'],
  ['PRM', 'PRM', '21'],
  ['TRUNK1', 'Trunk 1', '23'],
  ['TRUNK2', 'Trunk 2', '24'],
  ['RDP', 'RDP', '27'],
  ['IRTP', 'IRTP', '28'],
  ['ISOTP4', 'ISO-TP4', '29'],
  ['RSVP', 'RSVP', '46'],
  ['GRE', 'GRE', '47'],
  ['ESP', 'ESP', '50'],
  ['AH', 'AH', '51'],
  ['MOBILE', 'Mobile', '55'],
  ['IPv6NONXT', 'IPv6 no next header', '59'],
  ['IPIP', 'IP-in-IP', '94'],
  ['ETHERIP', 'EtherIP', '97'],
  ['ENCAP', 'Encapsulation', '98'],
  ['EIGRP', 'EIGRP', '88'],
  ['OSPFIGP', 'OSPF', '89'],
  ['PIM', 'PIM', '103'],
  ['VRRP', 'VRRP', '112'],
  ['L2TP', 'L2TP', '115'],
  ['SCTP', 'SCTP', '132'],
  ['FC', 'FC', '133'],
].map(([value = '', label = '', number = '']) => ({ value, label: `${label} (${number})` }));

function portValueForForm(
  protocol: PortProtocol,
  port: string,
  type: string,
  code: string,
  other: string,
) {
  if (protocol === 'TCP' || protocol === 'UDP') return `${protocol.toLowerCase()}/${port.trim()}`;
  if (protocol === 'ICMP') return `icmp/${type}/${code}`;
  if (protocol === 'IPV6_ICMP') return `ipv6-icmp/${type}/${code}`;
  return `other/${other}`;
}

function groupMemberOptions(objects: DelegatedContext['objects'], groupType: string) {
  const memberType =
    groupType === 'NETWORK_GROUP'
      ? 'NETWORK'
      : groupType === 'PORT_SERVICE_GROUP'
        ? 'PORT_SERVICE'
        : 'URL';
  return (objects ?? [])
    .filter((item) => {
      if (item.object_type !== memberType) return false;
      if (groupType === 'PORT_SERVICE_GROUP') {
        const protocol = item.normalized_value?.split('/', 1)[0]?.toLowerCase();
        return protocol === 'tcp' || protocol === 'udp';
      }
      return true;
    })
    .map((item) => ({ value: item.id, label: item.name }));
}

function defaultObjectChangeSetName(groupName: string) {
  const timestamp = new Date().toISOString().slice(0, 16).replace('T', ' ');
  return `${groupName} objects · ${timestamp} UTC`;
}

function providerObjectNamePreview(groupSlug: string, requestedName: string) {
  const component = requestedName
    .trim()
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^[-._]+|[-._]+$/g, '');
  return `${groupSlug}__${component}`;
}

function objectValueHelp(objectType: string) {
  if (objectType === 'NETWORK')
    return 'IPv4 or IPv6 host, CIDR subnet, or IP range within an authorized range, for example 10.10.10.1, 10.10.10.0/24, 2001:db8::1, or 2001:db8::1-2001:db8::ff.';
  if (objectType === 'PORT_SERVICE')
    return 'TCP and UDP use one port or ordered range; ICMP uses type and code; Other uses a protocol selection.';
  if (objectType === 'URL') return 'Hostname or URL value supported by the provider.';
  return 'Provider-normalized object value.';
}

function pendingObjectValueError(objectType: string, value: string) {
  if (objectType !== 'PORT_SERVICE') return '';
  const parsed = /^(tcp|udp)\/(\d{1,5})(?:-(\d{1,5}))?$/i.exec(value);
  if (/^(icmp|ipv6-icmp)\/[^/]+\/[^/]+$/i.test(value)) return '';
  if (/^other\/[A-Za-z0-9_-]+$/i.test(value)) return '';
  if (!parsed) return 'Enter a valid TCP/UDP port, ICMP type and code, or other protocol.';
  const start = Number(parsed[2]);
  const end = Number(parsed[3] ?? parsed[2]);
  const invalidRange = start < 1 || end > 65_535 || start > end;
  return invalidRange ? 'Port ranges must be ordered and between 1 and 65535.' : '';
}

function objectPreflightError(changeSet: ChangeSet, groupName: string) {
  for (const operation of changeSet.operations) {
    const denied = operation.validation_results.find((result) => result.allowed === false);
    const reason = typeof denied?.reason === 'string' ? denied.reason : '';
    const resolution = operation.resolution;
    if (resolution.kind === 'NAMING_CONFLICT') {
      const providerName =
        typeof resolution.provider_name === 'string' ? resolution.provider_name : 'that name';
      return `Name conflict: ${providerName} already exists with different content. Change the object name and submit again.`;
    }
    if (resolution.kind === 'SEMANTIC_CONFLICT') {
      return 'Value conflict: the object value is invalid for the selected object type. Correct it and submit again.';
    }
    if (reason === 'GROUP_PREFIX_MISMATCH') {
      return `Name conflict: the supplied prefix does not match ${groupName}. Enter the object name without a prefix; the ${groupName} prefix is added automatically.`;
    }
    if (resolution.kind === 'EQUIVALENT_REUSE' && reason === 'RESOURCE_NOT_USABLE') {
      const value =
        typeof resolution.normalized_value === 'string' ? ` (${resolution.normalized_value})` : '';
      return `An equivalent provider object${value} already exists, but ${groupName} does not have USE access to it. Grant that existing object to ${groupName} for this policy, then create a new ChangeSet.`;
    }
    if (reason === 'ACTION_NOT_GRANTED') {
      return `${groupName} is not granted permission to create this object type in the selected policy.`;
    }
    if (reason === 'PROVIDER_CAPABILITY_UNAVAILABLE') {
      return 'The selected provider connection does not currently support this object operation.';
    }
    if (reason) return `Preflight denied this object: ${humanize(reason)}.`;
  }
  return 'Preflight did not approve this object. Review the Changeset validation details.';
}

function dialogError(reason: unknown) {
  if (reason instanceof ApiError) return `${reason.message} Reference: ${reason.correlationId}`;
  return 'The object Changeset request failed.';
}

function useRecentActivityCutoff() {
  const [cutoff, setCutoff] = useState(0);
  useEffect(() => {
    const update = () => setCutoff(Date.now() - 120_000);
    const initial = window.setTimeout(update, 0);
    const timer = window.setInterval(update, 3_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, []);
  return cutoff;
}

function RuleLane({
  title,
  tone,
  children,
}: {
  title: string;
  tone: 'source' | 'destination';
  children: ReactNode;
}) {
  return (
    <div className={`fm-rule-lane fm-rule-lane-${tone}`}>
      <Text className="fm-rule-lane-title">{title}</Text>
      <div className="fm-rule-facts">{children}</div>
    </div>
  );
}

function RuleFact({ label, values }: { label: string; values: string[] }) {
  return (
    <div className="fm-rule-fact">
      <Text className="fm-rule-fact-label">{label}</Text>
      <div className="fm-rule-values">
        {values.length ? (
          values.map((value) => (
            <span className="fm-rule-value" key={value}>
              {value}
            </span>
          ))
        ) : (
          <span className="fm-rule-value fm-rule-value-empty">Any</span>
        )}
      </div>
    </div>
  );
}

function pendingOperationName(operation: ChangeSet['operations'][number]) {
  for (const value of [
    operation.resolution.provider_name,
    operation.payload.name,
    operation.payload.expected_provider_name,
  ]) {
    if (typeof value === 'string' && value.trim()) return value;
  }
  return operation.kind.includes('RULE') ? 'selected rule' : 'selected object';
}

function humanize(value: string) {
  const objectTypeLabels: Record<string, string> = {
    PORT_SERVICE: 'Port',
    PORT_SERVICE_GROUP: 'Port Group',
  };
  if (objectTypeLabels[value]) return objectTypeLabels[value];
  return value
    .toLowerCase()
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .replace(/\bIp\b/g, 'IP');
}

function capabilityGroups(capabilities: string[], objectCreate: string[]) {
  const assigned = new Set(capabilities);
  const groups = [
    {
      label: 'Policy',
      values: ['view', 'approve'].filter((value) => assigned.has(value)),
    },
    {
      label: 'Rules',
      values: ['create_rule', 'modify_rule', 'reorder_rule', 'delete_rule'].filter((value) =>
        assigned.has(value),
      ),
    },
    {
      label: 'Objects',
      values: [
        ...(objectCreate.length > 0
          ? [`create_object:${objectCreate.map((value) => humanize(value)).join(', ')}`]
          : []),
        'modify_object',
        'delete_object',
      ].filter((value) => value.startsWith('create_object:') || assigned.has(value)),
    },
  ];
  return groups.filter((group) => group.values.length > 0);
}

function formatCapability(value: string) {
  if (value.startsWith('create_object:')) {
    return `Create (${value.slice('create_object:'.length)})`;
  }
  return humanize(value);
}
