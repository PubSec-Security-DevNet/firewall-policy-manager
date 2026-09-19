import {
  Alert,
  AppShell,
  Badge,
  Card,
  Container,
  Group,
  Loader,
  SimpleGrid,
  Stack,
  Table,
  Tabs,
  Text,
  Title,
  Button,
  Select,
  TextInput,
  Textarea,
} from '@mantine/core';
import type { ReactNode } from 'react';

import type { Inventory, ProviderSummary } from '../api/client';

export function AppLayout({
  children,
  headerActions,
}: {
  children: ReactNode;
  headerActions?: ReactNode;
}) {
  return (
    <AppShell header={{ height: 64 }} padding="md">
      <AppShell.Header>
        <Container size="lg" h="100%">
          <Group h="100%" justify="space-between">
            <Title order={1} size="h3">
              Firewall Manager
            </Title>
            <Group>
              {headerActions}
              <Badge color="yellow" variant="light">
                Development mode
              </Badge>
            </Group>
          </Group>
        </Container>
      </AppShell.Header>
      <AppShell.Main>{children}</AppShell.Main>
    </AppShell>
  );
}

export function AppPage({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Container component="main" size="lg">
      <Stack gap="lg">
        <header>
          <Title order={2}>{title}</Title>
          <Text c="dimmed">{description}</Text>
        </header>
        {children}
      </Stack>
    </Container>
  );
}

export function AppLoadingState({ label }: { label: string }) {
  return (
    <Group role="status" aria-live="polite">
      <Loader size="sm" />
      <Text>{label}</Text>
    </Group>
  );
}

export function AppErrorState({ message, reference }: { message: string; reference?: string }) {
  return (
    <Alert color="red" title="Unable to load the overview" role="alert">
      {message}
      {reference ? ` Reference: ${reference}` : ''}
    </Alert>
  );
}

export function AppIdentityNotice({ email, role }: { email: string; role: string }) {
  return (
    <Alert color="yellow" title="Isolated development authentication">
      Signed in locally as {email} with the {role} role. This adapter cannot be enabled in
      production.
    </Alert>
  );
}

export function AppMetricGrid({ values }: { values: Record<string, number> }) {
  return (
    <SimpleGrid cols={{ base: 2, sm: 5 }} aria-label="Seeded inventory counts">
      {Object.entries(values).map(([name, value]) => (
        <Card component="section" withBorder key={name} padding="md">
          <Text size="xl" fw={700}>
            {value}
          </Text>
          <Text size="sm" c="dimmed">
            {name.replace('_', ' ')}
          </Text>
        </Card>
      ))}
    </SimpleGrid>
  );
}

export function AppProviderGrid({ providers }: { providers: ProviderSummary[] }) {
  return (
    <section aria-labelledby="provider-heading">
      <Title id="provider-heading" order={3} mb="sm">
        Mock provider discovery
      </Title>
      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        {providers.map((provider) => (
          <Card component="article" withBorder key={provider.provider} padding="lg">
            <Group justify="space-between" align="start">
              <div>
                <Text fw={700}>{provider.display_name}</Text>
                <Text size="sm" c="dimmed">
                  {provider.provider.toUpperCase()} · {provider.provider_version}
                </Text>
              </div>
              <Badge color="blue">Read only</Badge>
            </Group>
            <Text mt="md">
              {provider.policy_count} policies · {provider.object_count} objects
            </Text>
          </Card>
        ))}
      </SimpleGrid>
    </section>
  );
}

function StatusBadge({ value }: { value: string | null }) {
  const color = value === 'COMPLETED' || value === 'OBSERVED' ? 'green' : 'yellow';
  return <Badge color={color}>{value ?? 'Not synchronized'}</Badge>;
}

function EmptyRow({ columns }: { columns: number }) {
  return (
    <Table.Tr>
      <Table.Td colSpan={columns}>
        <Text c="dimmed">No resources were discovered in this scope.</Text>
      </Table.Td>
    </Table.Tr>
  );
}

export function AppInventoryBrowser({ inventory }: { inventory: Inventory }) {
  return (
    <section aria-labelledby="inventory-heading">
      <Title id="inventory-heading" order={3} mb="sm">
        Synchronized inventory
      </Title>
      <Tabs defaultValue="managers">
        <Tabs.List aria-label="Inventory resource type">
          <Tabs.Tab value="managers">Managers</Tabs.Tab>
          <Tabs.Tab value="policies">Policies</Tabs.Tab>
          <Tabs.Tab value="rules">Rules</Tabs.Tab>
          <Tabs.Tab value="objects">Objects</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="managers" pt="md">
          <div style={{ overflowX: 'auto' }}>
            <Table striped withTableBorder>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Provider</Table.Th>
                  <Table.Th>Version</Table.Th>
                  <Table.Th>Sync</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {inventory.managers.length === 0 && <EmptyRow columns={4} />}
                {inventory.managers.map((manager) => {
                  const status = inventory.statuses.find((item) => item.manager_id === manager.id);
                  return (
                    <Table.Tr key={manager.id}>
                      <Table.Td>{manager.display_name}</Table.Td>
                      <Table.Td>{manager.provider.toUpperCase()}</Table.Td>
                      <Table.Td>{manager.provider_version ?? 'Unknown'}</Table.Td>
                      <Table.Td>
                        <StatusBadge value={status?.sync_status ?? null} />
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="policies" pt="md">
          <ResourceTable
            rows={inventory.policies.map((item) => ({
              id: item.id,
              name: item.name,
              detail: `Revision ${item.revision}`,
              state: item.management_state,
            }))}
          />
        </Tabs.Panel>
        <Tabs.Panel value="rules" pt="md">
          <ResourceTable
            rows={inventory.rules.map((item) => ({
              id: item.id,
              name: item.name,
              detail: `${item.action} · position ${item.position}`,
              state: item.management_state,
            }))}
          />
        </Tabs.Panel>
        <Tabs.Panel value="objects" pt="md">
          <ResourceTable
            rows={inventory.objects.map((item) => ({
              id: item.id,
              name: item.name,
              detail: `${item.object_type} · ${item.sharing_mode}`,
              state: item.management_state,
            }))}
          />
        </Tabs.Panel>
      </Tabs>
    </section>
  );
}

function ResourceTable({
  rows,
}: {
  rows: Array<{ id: string; name: string; detail: string; state: string }>;
}) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <Table striped withTableBorder>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Name</Table.Th>
            <Table.Th>Details</Table.Th>
            <Table.Th>Management status</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.length === 0 && <EmptyRow columns={3} />}
          {rows.map((row) => (
            <Table.Tr key={row.id}>
              <Table.Td>{row.name}</Table.Td>
              <Table.Td>{row.detail}</Table.Td>
              <Table.Td>
                <StatusBadge value={row.state} />
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </div>
  );
}

// Semantic aliases keep feature code independent of Mantine import paths while the component
// catalog grows. Behavior, labels, and authorization remain in feature/view-model code.
export {
  Alert as AppAlert,
  Badge as AppBadge,
  Button as AppButton,
  Card as AppCard,
  Group as AppGroup,
  Select as AppSelect,
  SimpleGrid as AppSimpleGrid,
  Stack as AppStack,
  Table as AppTable,
  Text as AppText,
  TextInput as AppTextInput,
  Textarea as AppTextarea,
  Title as AppTitle,
};
