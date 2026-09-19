import type { ActiveGroup } from '../../api/client';
import {
  AppAlert as Alert,
  AppBadge as Badge,
  AppCard as Card,
  AppErrorState,
  AppGroup as Group,
  AppLoadingState,
  AppSelect as Select,
  AppSimpleGrid as SimpleGrid,
  AppStack as Stack,
  AppTable as Table,
  AppText as Text,
  AppTitle as Title,
} from '../../ui';
import { useDelegatedWorkspace } from './useDelegatedWorkspace';
import { ChangeSetPanel } from '../changesets/ChangeSetPanel';

export function DelegatedWorkspace({ groups }: { groups: ActiveGroup[] }) {
  const workspace = useDelegatedWorkspace(groups);
  const activeGroup = groups.find((group) => group.id === workspace.activeGroupId);

  return (
    <Stack gap="lg">
      <Card withBorder component="section" aria-labelledby="working-context-heading">
        <Title id="working-context-heading" order={3} size="h4">
          Delegated working context
        </Title>
        <SimpleGrid cols={{ base: 1, sm: 2 }} mt="sm">
          <Select
            label="Working as"
            placeholder="Select one Group"
            value={workspace.activeGroupId || null}
            onChange={(value) => workspace.setActiveGroupId(value ?? '')}
            data={groups.map((group) => ({ value: group.id, label: group.name }))}
            clearable={groups.length > 1}
          />
          <Select
            label="Access Policy"
            placeholder="Select a delegated policy"
            value={workspace.activePolicyId || null}
            onChange={(value) => workspace.setActivePolicyId(value ?? '')}
            data={
              workspace.state.status === 'loading' || workspace.state.status === 'ready'
                ? workspace.state.policies.map((policy) => ({
                    value: policy.id,
                    label: policy.name,
                  }))
                : []
            }
            disabled={!workspace.activeGroupId}
          />
        </SimpleGrid>
        {activeGroup && (
          <Group mt="md">
            <Badge size="lg" color="blue">
              Working as: {activeGroup.name}
            </Badge>
            {workspace.state.status === 'ready' && (
              <Badge size="lg" variant="light">
                Policy: {workspace.state.context.policy.name}
              </Badge>
            )}
          </Group>
        )}
      </Card>

      {workspace.state.status === 'unavailable' && (
        <Alert color="yellow" title="Delegated access unavailable">
          {workspace.state.reason}
        </Alert>
      )}
      {workspace.state.status === 'loading' && <AppLoadingState label="Recalculating access" />}
      {workspace.state.status === 'error' && (
        <AppErrorState
          message={workspace.state.message}
          reference={workspace.state.correlationId}
        />
      )}
      {workspace.state.status === 'ready' && (
        <>
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <EntitlementCard
              title="Authorized address space"
              values={workspace.state.context.ip_ranges}
            />
            <EntitlementCard
              title="Policy capabilities"
              values={workspace.state.context.capabilities}
            />
            <EntitlementCard
              title="Object creation"
              values={workspace.state.context.object_create.map(
                (item) =>
                  `${item.object_type}: ${item.provider_supported ? 'available' : 'provider unavailable'}`,
              )}
            />
          </SimpleGrid>
          <ResourceTable
            title="Group-owned rules"
            rows={workspace.state.context.rules.map((item) => [
              item.name,
              `${item.action} · position ${item.position}`,
            ])}
          />
          <ChangeSetPanel
            key={`${workspace.state.activeGroupId}-${workspace.state.activePolicyId}`}
            activeGroupId={workspace.state.activeGroupId}
            context={workspace.state.context}
          />
          <ResourceTable
            title="Objects authorized for USE"
            rows={workspace.state.context.objects.map((item) => [item.name, item.object_type])}
          />
          <ResourceTable
            title="Authorized zones"
            rows={workspace.state.context.zones.map((item) => [item.name, item.direction])}
          />
        </>
      )}
    </Stack>
  );
}

function EntitlementCard({ title, values }: { title: string; values: string[] }) {
  return (
    <Card withBorder component="section">
      <Text fw={700}>{title}</Text>
      {values.length === 0 ? (
        <Text c="dimmed" size="sm">
          None granted
        </Text>
      ) : (
        values.map((value) => (
          <Text key={value} size="sm">
            {value}
          </Text>
        ))
      )}
    </Card>
  );
}

function ResourceTable({ title, rows }: { title: string; rows: Array<[string, string]> }) {
  return (
    <section aria-label={title}>
      <Title order={3} size="h4" mb="xs">
        {title}
      </Title>
      <Table withTableBorder striped>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Name</Table.Th>
            <Table.Th>Scope</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.length === 0 ? (
            <Table.Tr>
              <Table.Td colSpan={2}>No resources are granted in this context.</Table.Td>
            </Table.Tr>
          ) : (
            rows.map(([name, detail]) => (
              <Table.Tr key={`${name}-${detail}`}>
                <Table.Td>{name}</Table.Td>
                <Table.Td>{detail}</Table.Td>
              </Table.Tr>
            ))
          )}
        </Table.Tbody>
      </Table>
    </section>
  );
}
