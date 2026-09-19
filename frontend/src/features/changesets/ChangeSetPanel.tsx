import { useEffect, useState } from 'react';

import {
  addDraftObject,
  addDraftRule,
  ApiError,
  changeSetAction,
  createChangeSet,
  loadChangeSets,
  type ChangeSet,
  type DelegatedContext,
} from '../../api/client';
import {
  AppAlert as Alert,
  AppBadge as Badge,
  AppButton as Button,
  AppCard as Card,
  AppGroup as Group,
  AppSelect as Select,
  AppSimpleGrid as SimpleGrid,
  AppStack as Stack,
  AppTable as Table,
  AppText as Text,
  AppTextarea as Textarea,
  AppTextInput as TextInput,
  AppTitle as Title,
} from '../../ui';

export function ChangeSetPanel({
  activeGroupId,
  context,
}: {
  activeGroupId: string;
  context: DelegatedContext;
}) {
  const [items, setItems] = useState<ChangeSet[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const selected = items.find((item) => item.id === selectedId);

  useEffect(() => {
    void loadChangeSets(activeGroupId)
      .then((rows) => {
        setItems(rows);
        setSelectedId(rows[0]?.id ?? '');
      })
      .catch((reason: unknown) => setError(message(reason)));
  }, [activeGroupId, context.policy.id]);

  const replace = (item: ChangeSet) => {
    setItems((current) => [item, ...current.filter((row) => row.id !== item.id)]);
    setSelectedId(item.id);
  };
  const run = async (work: () => Promise<ChangeSet>) => {
    setBusy(true);
    setError('');
    try {
      replace(await work());
    } catch (reason) {
      setError(message(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card withBorder component="section" aria-labelledby="changeset-heading">
      <Group justify="space-between" align="start">
        <div>
          <Title id="changeset-heading" order={3} size="h4">
            Draft ChangeSets
          </Title>
          <Text size="sm" c="dimmed">
            Execution targets deterministic mock providers only. Production writes and deployment
            are disabled.
          </Text>
        </div>
        <Badge color="yellow">Mock execution only</Badge>
      </Group>

      {error && (
        <Alert color="red" title="ChangeSet request failed" mt="md" role="alert">
          {error}
        </Alert>
      )}

      <SimpleGrid cols={{ base: 1, md: 2 }} mt="md">
        <Stack gap="xs">
          <TextInput
            label="ChangeSet name"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />
          <Textarea
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          <Button
            disabled={!title.trim() || busy}
            onClick={() =>
              void run(() =>
                createChangeSet(activeGroupId, context.policy.id, title.trim(), description),
              )
            }
          >
            Create draft
          </Button>
        </Stack>
        <Stack gap="xs">
          <Select
            label="Current ChangeSet"
            placeholder="Create or select a draft"
            value={selectedId || null}
            onChange={(value) => setSelectedId(value ?? '')}
            data={items.map((item) => ({
              value: item.id,
              label: `${item.title} · ${item.state}`,
            }))}
          />
          {selected && (
            <Group>
              <Badge color={selected.state === 'READY' ? 'green' : 'blue'}>{selected.state}</Badge>
              <Text size="sm">{selected.operations.length} operations</Text>
            </Group>
          )}
        </Stack>
      </SimpleGrid>

      {selected && (
        <Stack mt="lg">
          <DraftRuleForm
            context={context}
            disabled={busy || !editable(selected)}
            onAdd={(rule) => void run(() => addDraftRule(selected.id, activeGroupId, rule))}
          />
          <DraftObjectForm
            context={context}
            disabled={busy || !editable(selected)}
            onAdd={(object) => void run(() => addDraftObject(selected.id, activeGroupId, object))}
          />
          <Group>
            <Button
              variant="light"
              disabled={busy || !editable(selected)}
              onClick={() =>
                void run(() => changeSetAction(selected.id, activeGroupId, 'preflight'))
              }
            >
              Run preflight
            </Button>
            <Button
              variant="light"
              disabled={busy || !editable(selected)}
              onClick={() => void run(() => changeSetAction(selected.id, activeGroupId, 'refresh'))}
            >
              Check provider revisions
            </Button>
            <Button
              color="orange"
              disabled={busy || selected.state !== 'READY'}
              onClick={() => void run(() => changeSetAction(selected.id, activeGroupId, 'execute'))}
            >
              Execute against mock
            </Button>
          </Group>
          <ChangeSetResults item={selected} />
        </Stack>
      )}
    </Card>
  );
}

function DraftRuleForm({
  context,
  disabled,
  onAdd,
}: {
  context: DelegatedContext;
  disabled: boolean;
  onAdd: (value: Record<string, unknown>) => void;
}) {
  const [name, setName] = useState('');
  const [categoryId, setCategoryId] = useState(context.categories[0]?.id ?? '');
  const [sourceZoneId, setSourceZoneId] = useState('');
  const [destinationZoneId, setDestinationZoneId] = useState('');
  const [sourceObjectId, setSourceObjectId] = useState('');
  const [destinationObjectId, setDestinationObjectId] = useState('');
  const canCreate = context.capabilities.includes('create_rule');
  return (
    <Card withBorder>
      <Text fw={700}>Add normalized rule operation</Text>
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} mt="xs">
        <TextInput label="Rule name" value={name} onChange={(e) => setName(e.target.value)} />
        <Select
          label="Authorized category"
          value={categoryId || null}
          onChange={(value) => setCategoryId(value ?? '')}
          data={context.categories.map((item) => ({ value: item.id, label: item.name }))}
        />
        <Select
          label="Source zone"
          clearable
          value={sourceZoneId || null}
          onChange={(value) => setSourceZoneId(value ?? '')}
          data={context.zones
            .filter((item) => item.direction === 'SOURCE' || item.direction === 'BOTH')
            .map((item) => ({ value: item.id, label: item.name }))}
        />
        <Select
          label="Destination zone"
          clearable
          value={destinationZoneId || null}
          onChange={(value) => setDestinationZoneId(value ?? '')}
          data={context.zones
            .filter((item) => item.direction === 'DESTINATION' || item.direction === 'BOTH')
            .map((item) => ({ value: item.id, label: item.name }))}
        />
        <Select
          label="Source network object"
          clearable
          value={sourceObjectId || null}
          onChange={(value) => setSourceObjectId(value ?? '')}
          data={context.objects
            .filter((item) => item.object_type === 'NETWORK')
            .map((item) => ({ value: item.id, label: item.name }))}
        />
        <Select
          label="Destination network object"
          clearable
          value={destinationObjectId || null}
          onChange={(value) => setDestinationObjectId(value ?? '')}
          data={context.objects
            .filter((item) => item.object_type === 'NETWORK')
            .map((item) => ({ value: item.id, label: item.name }))}
        />
      </SimpleGrid>
      <Button
        mt="sm"
        disabled={disabled || !canCreate || !name.trim() || !categoryId}
        onClick={() =>
          onAdd({
            name: name.trim(),
            action: 'ALLOW',
            category_id: categoryId,
            source_zone_ids: sourceZoneId ? [sourceZoneId] : [],
            destination_zone_ids: destinationZoneId ? [destinationZoneId] : [],
            source_object_ids: sourceObjectId ? [sourceObjectId] : [],
            destination_object_ids: destinationObjectId ? [destinationObjectId] : [],
          })
        }
      >
        Add rule draft
      </Button>
    </Card>
  );
}

function DraftObjectForm({
  context,
  disabled,
  onAdd,
}: {
  context: DelegatedContext;
  disabled: boolean;
  onAdd: (value: Record<string, unknown>) => void;
}) {
  const options = context.object_create
    .filter((item) => item.provider_supported)
    .map((item) => ({ value: item.object_type, label: item.object_type }));
  const [objectType, setObjectType] = useState(options[0]?.value ?? '');
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  return (
    <Card withBorder>
      <Text fw={700}>Add object operation</Text>
      <SimpleGrid cols={{ base: 1, sm: 3 }} mt="xs">
        <Select
          label="Permitted type"
          data={options}
          value={objectType || null}
          onChange={(next) => setObjectType(next ?? '')}
        />
        <TextInput label="Object name" value={name} onChange={(e) => setName(e.target.value)} />
        <TextInput
          label="Normalized value"
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
      </SimpleGrid>
      <Button
        mt="sm"
        disabled={disabled || !objectType || !name.trim() || !value.trim()}
        onClick={() => onAdd({ name: name.trim(), object_type: objectType, value: value.trim() })}
      >
        Resolve and add object
      </Button>
    </Card>
  );
}

function ChangeSetResults({ item }: { item: ChangeSet }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <Table withTableBorder striped aria-label="ChangeSet validation and execution results">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Operation</Table.Th>
            <Table.Th>Status</Table.Th>
            <Table.Th>Resolution / result</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {item.operations.length === 0 ? (
            <Table.Tr>
              <Table.Td colSpan={3}>No draft operations yet.</Table.Td>
            </Table.Tr>
          ) : (
            item.operations.map((operation) => (
              <Table.Tr key={operation.id}>
                <Table.Td>{operation.kind}</Table.Td>
                <Table.Td>{operation.status}</Table.Td>
                <Table.Td>
                  {displayValue(
                    operation.resolution.kind ??
                      operation.execution_result.status ??
                      `${operation.validation_results.length} preflight checks`,
                  )}
                </Table.Td>
              </Table.Tr>
            ))
          )}
        </Table.Tbody>
      </Table>
      {Object.keys(item.failure_info).length > 0 && (
        <Alert color="red" title="Conflict or execution failure" mt="sm">
          {JSON.stringify(item.failure_info)}
        </Alert>
      )}
    </div>
  );
}

function editable(item: ChangeSet) {
  return ['DRAFT', 'VALIDATION_FAILED', 'READY'].includes(item.state);
}

function message(error: unknown) {
  return error instanceof ApiError
    ? `${error.message} Reference: ${error.correlationId}`
    : 'The request failed.';
}

function displayValue(value: unknown) {
  return typeof value === 'string' || typeof value === 'number'
    ? String(value)
    : 'Result available';
}
