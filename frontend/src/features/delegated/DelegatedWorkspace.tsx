import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  IconArrowRight,
  IconArrowsMoveVertical,
  IconCategory,
  IconEdit,
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
  AppDataTable,
  AppDialog as Dialog,
  AppEmptyState,
  AppErrorState,
  AppGroup as Group,
  AppLoadingState,
  AppMultiSelect as MultiSelect,
  AppPage,
  AppRadio as Radio,
  AppSelect as Select,
  AppSimpleGrid as SimpleGrid,
  AppStack as Stack,
  AppStatusBadge,
  AppTable as Table,
  AppText as Text,
  AppTextInput as TextInput,
  AppTitle as Title,
  MetricCard,
} from '../../ui';
import { ChangeSetPanel } from '../changesets/ChangeSetPanel';
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
  onNavigate,
}: {
  groups: ActiveGroup[];
  initialView?: WorkspaceView;
  initialGroupId?: string;
  initialPolicyId?: string;
  defaultGroupId?: string;
  defaultPolicyId?: string;
  onContextChange?: (groupId?: string, policyId?: string, group?: string, policy?: string) => void;
  onDefaultChange?: (groupId: string, policyId: string) => void;
  onNavigate?: (view: WorkspaceView) => void;
}) {
  const workspace = useDelegatedWorkspace(groups, initialGroupId, initialPolicyId);
  const [activity, setActivity] = useState<ChangeSet[]>([]);
  const view = initialView;
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
    if (!workspace.activeGroupId || !workspace.activePolicyId || view === 'policies') {
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
    const timer = window.setInterval(refresh, 3_000);
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
              ? 'ChangeSets'
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
          />
        </>
      )}
      {workspace.state.status === 'ready' && view === 'objects' && (
        <>
          <WorkspaceMetrics view="objects" context={workspace.state.context} />
          <ObjectsWorkspace
            context={workspace.state.context}
            groupName={activeGroup?.name ?? 'Current Group'}
            groupSlug={activeGroup?.provider_slug ?? 'GROUP'}
            activeGroupId={workspace.state.activeGroupId}
            activity={activity}
            onOpenChanges={() => onNavigate?.('changes')}
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
}: {
  view: 'rules' | 'objects';
  context: DelegatedContext;
}) {
  if (view === 'rules') {
    const allows = context.rules.filter((rule) => rule.action.toUpperCase() === 'ALLOW').length;
    const serviceScoped = context.rules.filter(
      (rule) =>
        (rule.source_services?.length ?? 0) > 0 || (rule.destination_services?.length ?? 0) > 0,
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
          value={context.rules.length - allows}
          detail="Block or inspect actions"
          icon={<IconShieldX size={19} />}
        />
        <MetricCard
          label="Service scoped"
          value={serviceScoped}
          detail="Rules matching ports"
          icon={<IconCategory size={19} />}
        />
      </SimpleGrid>
    );
  }
  const owned = context.objects.filter((object) => object.owner_type === 'GROUP').length;
  const objectTypes = new Set(context.objects.map((object) => object.object_type)).size;
  return (
    <SimpleGrid cols={{ base: 1, xs: 2, lg: 4 }}>
      <MetricCard
        label="Authorized objects"
        value={context.objects.length}
        detail="Visible in this policy"
        icon={<IconPackages size={19} />}
      />
      <MetricCard
        label="Group owned"
        value={owned}
        detail="Editable by this Group"
        icon={<IconUsersGroup size={19} />}
      />
      <MetricCard
        label="Provider shared"
        value={context.objects.length - owned}
        detail="Available for rule use"
        icon={<IconShieldCheck size={19} />}
      />
      <MetricCard
        label="Object types"
        value={objectTypes}
        detail="Networks, ports, and more"
        icon={<IconCategory size={19} />}
      />
    </SimpleGrid>
  );
}

type PolicyMapping = {
  group: ActiveGroup;
  policy: DelegatedPolicy;
  capabilities: string[];
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

  useEffect(() => {
    let current = true;
    void Promise.all(
      groups.map(async (group) => {
        const policies = await loadDelegatedPolicies(group.id);
        return policies.map((policy) => ({
          group,
          policy,
          capabilities: [],
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
                        <div className="fm-policy-access-summary">
                          <Text size="xs" fw={700}>
                            Rights
                          </Text>
                          <Text size="xs" c="dimmed">
                            {!mapping.authorizationLoaded
                              ? 'Loading…'
                              : mapping.capabilities.length > 0
                                ? mapping.capabilities.map(humanize).join(' · ')
                                : 'None assigned'}
                          </Text>
                          <Text size="xs" fw={700}>
                            IP ranges
                          </Text>
                          <Text size="xs" c="dimmed" className="fm-code">
                            {!mapping.authorizationLoaded
                              ? 'Loading…'
                              : mapping.ipRanges.length > 0
                                ? mapping.ipRanges.join(' · ')
                                : 'None assigned'}
                          </Text>
                        </div>
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
      </AppCard>
    </Stack>
  );
}

function RulesWorkspace({
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
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<DelegatedContext['rules'][number]>();
  const [deleting, setDeleting] = useState<DelegatedContext['rules'][number]>();
  const [deletePendingIds, setDeletePendingIds] = useState<string[]>([]);
  const [deleteNotice, setDeleteNotice] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const recentCutoff = useRecentActivityCutoff();
  const trackedRuleOperations = activity
    .filter(
      (changeSet) =>
        changeSet.access_policy_id === context.policy.id &&
        (['QUEUED', 'EXECUTING'].includes(changeSet.state) ||
          (['SUCCEEDED', 'FAILED', 'CONFLICT', 'PARTIALLY_SUCCEEDED'].includes(changeSet.state) &&
            Date.parse(changeSet.updated_at) >= recentCutoff)),
    )
    .flatMap((changeSet) =>
      changeSet.operations
        .filter((operation) => ['CREATE_RULE', 'DELETE_RULE'].includes(operation.kind))
        .map((operation) => ({ changeSet, operation })),
    );
  const activeRuleOperations = trackedRuleOperations.filter(({ changeSet }) =>
    ['QUEUED', 'EXECUTING'].includes(changeSet.state),
  );
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
      <CreateRuleDialog
        opened={creating}
        onClose={() => setCreating(false)}
        activeGroupId={activeGroupId}
        groupName={groupName}
        groupSlug={groupSlug}
        context={context}
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
        key={editing ? `${editing.id}:${editing.revision}` : 'closed'}
        rule={editing}
        onClose={() => setEditing(undefined)}
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
          <AppStatusBadge
            value={
              context.provider_writable && context.capabilities.includes('reorder_rule')
                ? 'ACTIVE'
                : 'READ_ONLY'
            }
            label={
              context.provider_writable && context.capabilities.includes('reorder_rule')
                ? 'Reorder enabled'
                : 'Ordering read only'
            }
          />
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
      {trackedRuleOperations.length > 0 && (
        <AppCard className="fm-subtle-panel" mb="md">
          <Group justify="space-between" mb="xs">
            <Text fw={700} size="sm">
              {activeRuleOperations.length ? 'Rule changes in progress' : 'Recent rule changes'}
            </Text>
            {activeRuleOperations.length > 0 && (
              <AppStatusBadge
                value="EXECUTING"
                label={`${activeRuleOperations.length} processing`}
              />
            )}
          </Group>
          <Stack gap={6}>
            {trackedRuleOperations.map(({ changeSet, operation }) => (
              <Group key={operation.id} justify="space-between">
                <Text size="sm">
                  {operation.kind === 'DELETE_RULE' ? 'Deleting' : 'Creating'}{' '}
                  {pendingOperationName(operation)}
                </Text>
                <AppStatusBadge value={changeSet.state} />
              </Group>
            ))}
          </Stack>
        </AppCard>
      )}
      {filtered.length === 0 ? (
        <AppEmptyState
          title={context.rules.length ? 'No matching rules' : 'No Group-owned rules'}
          description={
            context.rules.length
              ? 'Clear or refine the current search.'
              : 'Create a ChangeSet draft to add the first rule in this delegated category.'
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
                    <Text fw={750} className="fm-rule-title">
                      {rule.name}
                    </Text>
                    <Text size="10px" c="dimmed">
                      Revision {rule.revision}
                    </Text>
                  </div>
                </div>
                <Group gap="xs" wrap="wrap" justify="flex-end">
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
                  <AppStatusBadge value={rule.management_state} />
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
                      deletePendingIds.includes(rule.id)
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
      {orderQueued && (
        <Alert mt="md" color="blue" title="Rule order queued">
          ChangeSet {orderQueued.title} was created, preflighted, and submitted. Its status and
          details are available on the ChangeSets page.
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
      <Alert mt="sm" color="yellow" title="Provider reorder behavior">
        FMC and SCC do not expose an update-in-place rule-order operation. Saving an order recreates
        only the moved rules at their selected positions, so their provider-native IDs and provider
        hit-count history may change.
      </Alert>
    </AppCard>
  );
}

function CreateRuleDialog({
  opened,
  onClose,
  activeGroupId,
  groupName,
  groupSlug,
  context,
}: {
  opened: boolean;
  onClose: () => void;
  activeGroupId: string;
  groupName: string;
  groupSlug: string;
  context: DelegatedContext;
}) {
  const [changeSetName, setChangeSetName] = useState(() => defaultRuleChangeSetName(groupName));
  const [name, setName] = useState('');
  const [action, setAction] = useState('ALLOW');
  const [sourceZoneIds, setSourceZoneIds] = useState<string[]>([]);
  const [destinationZoneIds, setDestinationZoneIds] = useState<string[]>([]);
  const [sourceObjectIds, setSourceObjectIds] = useState<string[]>([]);
  const [destinationObjectIds, setDestinationObjectIds] = useState<string[]>([]);
  const [sourcePortObjectIds, setSourcePortObjectIds] = useState<string[]>([]);
  const [destinationPortObjectIds, setDestinationPortObjectIds] = useState<string[]>([]);
  const orderedExistingRules = [...context.rules].sort(
    (left, right) => left.position - right.position,
  );
  const [placement, setPlacement] = useState<string | null>(
    defaultRulePlacement(orderedExistingRules),
  );
  const [rules, setRules] = useState<PendingRule[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [prepared, setPrepared] = useState<ChangeSet>();
  const [queued, setQueued] = useState<ChangeSet>();

  const sourceZones = context.zones
    .filter((zone) => zone.direction !== 'DESTINATION')
    .map(selectOption);
  const destinationZones = context.zones
    .filter((zone) => zone.direction !== 'SOURCE')
    .map(selectOption);
  const networkObjects = context.objects
    .filter((object) => ['NETWORK', 'NETWORK_GROUP'].includes(object.object_type))
    .map(selectOption);
  const portObjects = context.objects
    .filter((object) => object.object_type === 'PORT_SERVICE')
    .map(selectOption);
  const clearRuleFields = () => {
    setName('');
    setAction('ALLOW');
    setSourceZoneIds([]);
    setDestinationZoneIds([]);
    setSourceObjectIds([]);
    setDestinationObjectIds([]);
    setSourcePortObjectIds([]);
    setDestinationPortObjectIds([]);
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
    onClose();
  };
  const addRule = () => {
    const cleanName = name.trim();
    if (!cleanName) return;
    const providerName = providerRuleName(groupSlug, cleanName).toLocaleLowerCase();
    if (
      rules.some(
        (rule) => providerRuleName(groupSlug, rule.name).toLocaleLowerCase() === providerName,
      )
    ) {
      setError('Each rule in this ChangeSet must have a unique name.');
      return;
    }
    setRules((current) => [
      ...current,
      {
        id: `${Date.now()}-${current.length}`,
        name: cleanName,
        action,
        source_zone_ids: sourceZoneIds,
        destination_zone_ids: destinationZoneIds,
        source_object_ids: sourceObjectIds,
        destination_object_ids: destinationObjectIds,
        source_port_object_ids: sourcePortObjectIds,
        destination_port_object_ids: destinationPortObjectIds,
        ...(orderedExistingRules.length
          ? rulePlacementPayload(placement, orderedExistingRules)
          : {}),
        ...(orderedExistingRules[0]?.category_id
          ? { category_id: orderedExistingRules[0].category_id }
          : {}),
      },
    ]);
    setError('');
    clearRuleFields();
  };
  const editRule = (rule: PendingRule) => {
    setName(rule.name);
    setAction(rule.action);
    setSourceZoneIds(rule.source_zone_ids);
    setDestinationZoneIds(rule.destination_zone_ids);
    setSourceObjectIds(rule.source_object_ids);
    setDestinationObjectIds(rule.destination_object_ids);
    setSourcePortObjectIds(rule.source_port_object_ids);
    setDestinationPortObjectIds(rule.destination_port_object_ids);
    setPlacement(rulePlacementValue(rule));
    setRules((current) => current.filter((item) => item.id !== rule.id));
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
      if (validated.state !== 'READY') setError(rulePreflightError(validated));
    } catch (reason) {
      setError(ruleDialogError(reason));
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
      setError(ruleDialogError(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      opened={opened}
      onClose={resetAndClose}
      title="Create firewall rule"
      centered
      size="xl"
      classNames={{ content: 'fm-object-dialog', body: 'fm-object-dialog-body' }}
      closeOnClickOutside={!busy}
      closeOnEscape={!busy}
    >
      <Stack gap="md">
        {!prepared && !queued && (
          <>
            <Text size="sm" c="dimmed">
              Add one or more rules for {groupName} and {context.policy.name}. One ChangeSet is
              created and preflighted without leaving this page.
            </Text>
            <TextInput
              label="ChangeSet name"
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
                onChange={(value) => setAction(value ?? 'ALLOW')}
                data={['ALLOW', 'BLOCK', 'TRUST', 'MONITOR']}
                disabled={busy}
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
            </SimpleGrid>
            <Button
              variant="light"
              disabled={!name.trim() || busy || (orderedExistingRules.length > 0 && !placement)}
              onClick={addRule}
            >
              Add rule to ChangeSet
            </Button>
            {rules.length > 0 && (
              <div className="fm-object-basket">
                <AppDataTable label="Rules in this ChangeSet">
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
                                setRules((current) => current.filter((item) => item.id !== rule.id))
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
          <Alert color="red" title="Rule creation could not continue" role="alert">
            {error}
          </Alert>
        )}
        {prepared && !queued && (
          <AppCard className="fm-subtle-panel">
            <Text fw={700}>
              {prepared.state === 'READY' ? 'Ready to create' : 'Preflight result'}
            </Text>
            <Text size="sm" mt={5}>
              {prepared.title} · {rules.length} rule operation
              {rules.length === 1 ? '' : 's'}
            </Text>
            <Text size="xs" c="dimmed" mt={5}>
              {context.provider_name} ({context.provider_type.toUpperCase()}) ·{' '}
              {context.policy.name} · {groupName}
            </Text>
            <AppStatusBadge value={prepared.state} />
          </AppCard>
        )}
        {queued && (
          <Alert color="blue" title="Rule creation queued">
            ChangeSet {queued.title} is queued against {context.provider_name}. Provider deployment
            is not started and may later include pending changes outside this ChangeSet. The rules
            will appear after execution and synchronization complete.
          </Alert>
        )}
        <Group justify="flex-end">
          {prepared && prepared.state !== 'READY' && !queued && (
            <Button
              variant="light"
              onClick={() => {
                setPrepared(undefined);
                setError('');
              }}
              disabled={busy}
            >
              Back and edit rules
            </Button>
          )}
          <Button variant="subtle" onClick={resetAndClose} disabled={busy}>
            {queued || (prepared && prepared.state !== 'READY') ? 'Close' : 'Cancel'}
          </Button>
          {!prepared && !queued && (
            <Button
              loading={busy}
              disabled={!changeSetName.trim() || rules.length === 0}
              onClick={() => void prepare()}
            >
              Review {rules.length} rule{rules.length === 1 ? '' : 's'}
            </Button>
          )}
          {prepared && !queued && (
            <Button
              color="orange"
              loading={busy}
              disabled={prepared.state !== 'READY'}
              onClick={() => void execute()}
            >
              Create {rules.length} rule{rules.length === 1 ? '' : 's'} on provider
            </Button>
          )}
        </Group>
      </Stack>
    </Dialog>
  );
}

function EditRuleDialog({
  rule,
  onClose,
  activeGroupId,
  groupName,
  groupSlug,
  context,
}: {
  rule: DelegatedContext['rules'][number] | undefined;
  onClose: () => void;
  activeGroupId: string;
  groupName: string;
  groupSlug: string;
  context: DelegatedContext;
}) {
  const [name, setName] = useState(() => (rule ? editableRuleName(groupSlug, rule.name) : ''));
  const [action, setAction] = useState(() => rule?.action ?? 'ALLOW');
  const [sourceZoneIds, setSourceZoneIds] = useState<string[]>(() =>
    rule ? idsForNames(context.zones, rule.source_zones ?? []) : [],
  );
  const [destinationZoneIds, setDestinationZoneIds] = useState<string[]>(() =>
    rule ? idsForNames(context.zones, rule.destination_zones ?? []) : [],
  );
  const [sourceObjectIds, setSourceObjectIds] = useState<string[]>(() =>
    rule ? idsForNames(context.objects, rule.source_networks ?? []) : [],
  );
  const [destinationObjectIds, setDestinationObjectIds] = useState<string[]>(() =>
    rule ? idsForNames(context.objects, rule.destination_networks ?? []) : [],
  );
  const [sourcePortObjectIds, setSourcePortObjectIds] = useState<string[]>(() =>
    rule ? idsForNames(context.objects, rule.source_services ?? []) : [],
  );
  const [destinationPortObjectIds, setDestinationPortObjectIds] = useState<string[]>(() =>
    rule ? idsForNames(context.objects, rule.destination_services ?? []) : [],
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [prepared, setPrepared] = useState<ChangeSet>();
  const [queued, setQueued] = useState<ChangeSet>();
  const sourceZones = context.zones
    .filter((zone) => zone.direction !== 'DESTINATION')
    .map(selectOption);
  const destinationZones = context.zones
    .filter((zone) => zone.direction !== 'SOURCE')
    .map(selectOption);
  const networkObjects = context.objects
    .filter((object) => ['NETWORK', 'NETWORK_GROUP'].includes(object.object_type))
    .map(selectOption);
  const portObjects = context.objects
    .filter((object) => object.object_type === 'PORT_SERVICE')
    .map(selectOption);

  const close = () => {
    if (busy) return;
    setError('');
    setPrepared(undefined);
    setQueued(undefined);
    onClose();
  };
  const prepare = async () => {
    if (!rule || !name.trim()) return;
    setBusy(true);
    setError('');
    try {
      const draft = await createChangeSet(
        activeGroupId,
        context.policy.id,
        `${groupName} rule update · ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`,
        `Update ${rule.name} from the Rules workspace.`,
      );
      const withRule = await addDraftRule(
        draft.id,
        activeGroupId,
        {
          rule_id: rule.id,
          name: providerRuleName(groupSlug, name),
          action,
          source_zone_ids: sourceZoneIds,
          destination_zone_ids: destinationZoneIds,
          source_object_ids: sourceObjectIds,
          destination_object_ids: destinationObjectIds,
          source_port_object_ids: sourcePortObjectIds,
          destination_port_object_ids: destinationPortObjectIds,
        },
        'MODIFY_RULE',
      );
      const validated = await changeSetAction(withRule.id, activeGroupId, 'preflight');
      setPrepared(validated);
      if (validated.state !== 'READY') setError(rulePreflightError(validated));
    } catch (reason) {
      setError(ruleDialogError(reason));
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
      setError(ruleDialogError(reason));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      opened={Boolean(rule)}
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
                onChange={(value) => setAction(value ?? 'ALLOW')}
                data={['ALLOW', 'BLOCK', 'TRUST', 'MONITOR']}
                disabled={busy}
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
            </SimpleGrid>
          </>
        )}
        {error && (
          <Alert color="red" title="Rule update could not continue" role="alert">
            {error}
          </Alert>
        )}
        {prepared && !queued && (
          <AppCard className="fm-subtle-panel">
            <Text fw={700}>
              {prepared.state === 'READY' ? 'Ready to update' : 'Preflight result'}
            </Text>
            <Text size="sm" mt={5}>
              {prepared.title}
            </Text>
            <AppStatusBadge value={prepared.state} />
          </AppCard>
        )}
        {queued && (
          <Alert color="blue" title="Rule update queued">
            ChangeSet {queued.title} is visible on the ChangeSets page with its execution status.
          </Alert>
        )}
        <Group justify="flex-end">
          {prepared && prepared.state !== 'READY' && !queued && (
            <Button
              variant="light"
              onClick={() => {
                setPrepared(undefined);
                setError('');
              }}
              disabled={busy}
            >
              Back and edit
            </Button>
          )}
          <Button variant="subtle" onClick={close} disabled={busy}>
            {queued ? 'Close' : 'Cancel'}
          </Button>
          {!prepared && !queued && (
            <Button loading={busy} disabled={!name.trim()} onClick={() => void prepare()}>
              Review update
            </Button>
          )}
          {prepared && !queued && (
            <Button
              color="orange"
              loading={busy}
              disabled={prepared.state !== 'READY'}
              onClick={() => void execute()}
            >
              Update rule on provider
            </Button>
          )}
        </Group>
      </Stack>
    </Dialog>
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
            This queues a reviewed ChangeSet in the background. Only this Group-owned rule will be
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
  source_zone_ids: string[];
  destination_zone_ids: string[];
  source_object_ids: string[];
  destination_object_ids: string[];
  source_port_object_ids: string[];
  destination_port_object_ids: string[];
  category_id?: string;
  position?: number;
  placement?: 'BEFORE' | 'AFTER';
  anchor_rule_id?: string;
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

function ruleElementCount(rule: PendingRule) {
  return (
    rule.source_zone_ids.length +
    rule.destination_zone_ids.length +
    rule.source_object_ids.length +
    rule.destination_object_ids.length +
    rule.source_port_object_ids.length +
    rule.destination_port_object_ids.length
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
  return 'Preflight did not approve this rule. Review the ChangeSet validation details.';
}

function ruleDialogError(reason: unknown) {
  return reason instanceof ApiError
    ? `${reason.message} Reference: ${reason.correlationId}`
    : 'The rule ChangeSet request failed.';
}

function ObjectsWorkspace({
  context,
  groupName,
  groupSlug,
  activeGroupId,
  activity,
  onOpenChanges,
}: {
  context: DelegatedContext;
  groupName: string;
  groupSlug: string;
  activeGroupId: string;
  activity: ChangeSet[];
  onOpenChanges: () => void;
}) {
  const [query, setQuery] = useState('');
  const [type, setType] = useState<string | null>('ALL');
  const [creating, setCreating] = useState(false);
  const recentCutoff = useRecentActivityCutoff();
  const trackedObjectOperations = activity
    .filter(
      (changeSet) =>
        changeSet.access_policy_id === context.policy.id &&
        (['QUEUED', 'EXECUTING'].includes(changeSet.state) ||
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
  const activeObjectOperations = trackedObjectOperations.filter(({ changeSet }) =>
    ['QUEUED', 'EXECUTING'].includes(changeSet.state),
  );
  const rows = context.objects.filter(
    (item) =>
      item.name.toLowerCase().includes(query.toLowerCase()) &&
      (type === 'ALL' || item.object_type === type),
  );
  const types = [...new Set(context.objects.map((item) => item.object_type))];
  return (
    <AppCard>
      <Group justify="space-between" align="end" mb="md">
        <div>
          <Text className="fm-eyebrow">Authorized inventory</Text>
          <Title order={2} size="h4">
            Objects usable by {groupName}
          </Title>
          <Text size="xs" c="dimmed">
            USE does not imply MODIFY. Application ownership remains authoritative.
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
        opened={creating}
        onClose={() => setCreating(false)}
        activeGroupId={activeGroupId}
        groupName={groupName}
        groupSlug={groupSlug}
        context={context}
      />
      <Group mb="md">
        <TextInput
          aria-label="Search objects"
          placeholder="Search objects"
          leftSection={<IconSearch size={15} />}
          value={query}
          onChange={(event) => setQuery(event.currentTarget.value)}
        />
        <Select
          aria-label="Filter object type"
          value={type}
          onChange={setType}
          data={[
            { value: 'ALL', label: 'All object types' },
            ...types.map((value) => ({ value, label: humanize(value) })),
          ]}
        />
      </Group>
      {trackedObjectOperations.length > 0 && (
        <AppCard className="fm-subtle-panel" mb="md">
          <Group justify="space-between" mb="xs">
            <Text fw={700} size="sm">
              {activeObjectOperations.length
                ? 'Object changes in progress'
                : 'Recent object changes'}
            </Text>
            {activeObjectOperations.length > 0 && (
              <AppStatusBadge
                value="EXECUTING"
                label={`${activeObjectOperations.length} processing`}
              />
            )}
          </Group>
          <Stack gap={6}>
            {trackedObjectOperations.map(({ changeSet, operation }) => (
              <Group key={operation.id} justify="space-between">
                <Text size="sm">
                  {operation.kind === 'DELETE_OBJECT'
                    ? 'Deleting'
                    : operation.kind === 'MODIFY_OBJECT'
                      ? 'Updating'
                      : 'Creating'}{' '}
                  {pendingOperationName(operation)}
                </Text>
                <AppStatusBadge value={changeSet.state} />
              </Group>
            ))}
          </Stack>
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
              <Table.Th>Ownership</Table.Th>
              <Table.Th>Access</Table.Th>
              <Table.Th>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((object) => {
              const owned = object.owner_type === 'GROUP';
              return (
                <Table.Tr key={object.id}>
                  <Table.Td>
                    <Text fw={650}>{object.name}</Text>
                  </Table.Td>
                  <Table.Td>{humanize(object.object_type)}</Table.Td>
                  <Table.Td>
                    <AppStatusBadge
                      value={owned ? 'OWNED' : 'SHARED'}
                      label={owned ? `Owned by ${groupName}` : 'Provider / shared'}
                    />
                    {activeObjectOperations.some(
                      ({ operation }) =>
                        ['MODIFY_OBJECT', 'DELETE_OBJECT'].includes(operation.kind) &&
                        operation.payload.object_id === object.id,
                    ) && <AppStatusBadge value="EXECUTING" label="Processing" />}
                  </Table.Td>
                  <Table.Td>
                    <AppStatusBadge
                      value={owned ? 'ACTIVE' : 'READ_ONLY'}
                      label={owned ? 'Use and manage' : 'USE only'}
                    />
                  </Table.Td>
                  <Table.Td>
                    <Button
                      size="xs"
                      variant="subtle"
                      disabled={!owned || !context.capabilities.includes('modify_object')}
                      onClick={onOpenChanges}
                    >
                      Edit
                    </Button>
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </AppDataTable>
      )}
    </AppCard>
  );
}

function CreateObjectDialog({
  opened,
  onClose,
  activeGroupId,
  groupName,
  groupSlug,
  context,
}: {
  opened: boolean;
  onClose: () => void;
  activeGroupId: string;
  groupName: string;
  groupSlug: string;
  context: DelegatedContext;
}) {
  const options = context.object_create
    .filter((item) => item.provider_supported)
    .map((item) => ({ value: item.object_type, label: humanize(item.object_type) }));
  const [objectType, setObjectType] = useState(options[0]?.value ?? '');
  const [portProtocol, setPortProtocol] = useState('tcp');
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [changeSetName, setChangeSetName] = useState(() => defaultObjectChangeSetName(groupName));
  const [objects, setObjects] = useState<PendingObject[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [prepared, setPrepared] = useState<ChangeSet>();
  const [queued, setQueued] = useState<ChangeSet>();

  const resetAndClose = () => {
    if (busy) return;
    setObjectType(options[0]?.value ?? '');
    setPortProtocol('tcp');
    setName('');
    setValue('');
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
    if (!objectType || !cleanName || !enteredValue) return;
    const cleanValue =
      objectType === 'PORT_SERVICE' ? `${portProtocol}/${enteredValue}` : enteredValue;
    if (objects.some((item) => item.name.toLocaleLowerCase() === cleanName.toLocaleLowerCase())) {
      setError('Each object in this ChangeSet must have a unique name.');
      return;
    }
    const valueError = pendingObjectValueError(objectType, cleanValue);
    if (valueError) {
      setError(valueError);
      return;
    }
    setError('');
    setObjects((current) => [
      ...current,
      {
        id: `${Date.now()}-${current.length}`,
        object_type: objectType,
        name: cleanName,
        value: cleanValue,
      },
    ]);
    setName('');
    setValue('');
  };
  const editObject = (object: PendingObject) => {
    setObjectType(object.object_type);
    setName(object.name);
    if (object.object_type === 'PORT_SERVICE') {
      const [protocol, port] = object.value.split('/', 2);
      setPortProtocol(protocol || 'tcp');
      setValue(port || '');
    } else {
      setValue(object.value);
    }
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
        });
      }
      const validated = await changeSetAction(withObjects.id, activeGroupId, 'preflight');
      setPrepared(validated);
      if (validated.state !== 'READY') {
        setError(objectPreflightError(validated, groupName));
      }
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
              Add one or more objects for {groupName} and {context.policy.name}. One ChangeSet is
              created and preflighted without leaving this page.
            </Text>
            <TextInput
              label="ChangeSet name"
              value={changeSetName}
              onChange={(event) => setChangeSetName(event.currentTarget.value)}
              disabled={busy}
            />
            <Select
              label="Object type"
              data={options}
              value={objectType || null}
              onChange={(next) => {
                setObjectType(next ?? '');
                setValue('');
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
            {objectType === 'PORT_SERVICE' && (
              <Radio.Group
                name="port-protocol"
                label="Protocol"
                description="FMC port service objects support one TCP or UDP port definition."
                value={portProtocol}
                onChange={setPortProtocol}
              >
                <Group mt="xs">
                  <Radio value="tcp" label="TCP" disabled={busy} />
                  <Radio value="udp" label="UDP" disabled={busy} />
                </Group>
              </Radio.Group>
            )}
            <TextInput
              label={objectType === 'PORT_SERVICE' ? 'Port' : 'Value'}
              description={objectValueHelp(objectType)}
              value={value}
              onChange={(event) => setValue(event.currentTarget.value)}
              disabled={busy}
            />
            <Button
              variant="light"
              disabled={!objectType || !name.trim() || !value.trim() || busy}
              onClick={addObject}
            >
              Add object to ChangeSet
            </Button>
            {objects.length > 0 && (
              <div className="fm-object-basket">
                <AppDataTable label="Objects in this ChangeSet">
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
            color="red"
            title={
              /conflict|already exists/i.test(error)
                ? 'Object conflict'
                : 'Object creation could not continue'
            }
            role="alert"
          >
            {error}
          </Alert>
        )}
        {prepared && !queued && (
          <AppCard className="fm-subtle-panel">
            <Text fw={700}>
              {prepared.state === 'READY' ? 'Ready to create' : 'Preflight result'}
            </Text>
            <Text size="sm" mt={5}>
              {prepared.title} · {prepared.operations.length} object operation
              {prepared.operations.length === 1 ? '' : 's'}
            </Text>
            <Text size="xs" c="dimmed" mt={5}>
              {context.provider_name} ({context.provider_type.toUpperCase()}) ·{' '}
              {context.policy.name} · {groupName}
            </Text>
            <AppStatusBadge value={prepared.state} />
          </AppCard>
        )}
        {queued && (
          <Alert color="blue" title="Object creation queued">
            ChangeSet {queued.title} is queued against {context.provider_name}. Provider deployment
            is not started and may later include pending changes outside this ChangeSet. The
            reconciled object will appear after execution completes.
          </Alert>
        )}
        <Group justify="flex-end">
          {prepared && prepared.state !== 'READY' && !queued && (
            <Button variant="light" onClick={returnToBasket} disabled={busy}>
              Back and edit objects
            </Button>
          )}
          <Button variant="subtle" onClick={resetAndClose} disabled={busy}>
            {queued || (prepared && prepared.state !== 'READY') ? 'Close' : 'Cancel'}
          </Button>
          {!prepared && !queued && (
            <Button
              loading={busy}
              disabled={!changeSetName.trim() || objects.length === 0}
              onClick={() => void prepare()}
            >
              Review {objects.length} object{objects.length === 1 ? '' : 's'}
            </Button>
          )}
          {prepared && !queued && (
            <Button
              color="orange"
              loading={busy}
              disabled={prepared.state !== 'READY'}
              onClick={() => void execute()}
            >
              Create {objects.length} object{objects.length === 1 ? '' : 's'} on provider
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
    return 'Individual IP, CIDR subnet, or IP range within an authorized range, for example 10.10.10.1, 10.10.10.0/24, or 10.10.10.1-10.10.20.30.';
  if (objectType === 'PORT_SERVICE')
    return 'One port or one ordered port range, for example 443 or 8000-8080.';
  if (objectType === 'URL') return 'Hostname or URL value supported by the provider.';
  return 'Provider-normalized object value.';
}

function pendingObjectValueError(objectType: string, value: string) {
  if (objectType !== 'PORT_SERVICE') return '';
  const parsed = /^(tcp|udp)\/(\d{1,5})(?:-(\d{1,5}))?$/i.exec(value);
  if (!parsed) return 'Enter one port or one port range.';
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
  return 'Preflight did not approve this object. Review the ChangeSet validation details.';
}

function dialogError(reason: unknown) {
  if (reason instanceof ApiError) return `${reason.message} Reference: ${reason.correlationId}`;
  return 'The object ChangeSet request failed.';
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
  return value
    .toLowerCase()
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .replace(/\bIp\b/g, 'IP');
}
