import { useCallback, useEffect, useState } from 'react';
import {
  IconActivityHeartbeat,
  IconCloudCheck,
  IconDatabase,
  IconKey,
  IconPlus,
  IconRefresh,
  IconSettings,
  IconShieldCheck,
} from '@tabler/icons-react';

import {
  ApiError,
  createProviderConnection,
  forceProviderDeployment,
  loadDeployments,
  loadProviderConnections,
  loadProviderGuidance,
  requestProviderSync,
  rotateProviderCredential,
  setProviderConnectionLifecycle,
  setProviderConnectionWriteGate,
  testProviderConnection,
  updateProviderConnection,
  type ProviderConnection,
  type ProviderGuidance,
} from '../../api/client';
import {
  AppAlert as Alert,
  AppActionButton as ActionButton,
  AppButton as Button,
  AppCard as Card,
  AppDialog as Dialog,
  AppErrorState,
  AppEmptyState,
  AppGroup as Group,
  AppLoadingState,
  AppProviderBadge,
  AppSection,
  AppSelect as Select,
  AppSimpleGrid as SimpleGrid,
  AppStack as Stack,
  AppText as Text,
  AppTextarea as Textarea,
  AppTextInput as TextInput,
  AppStatusBadge,
  AppThemeIcon as ThemeIcon,
  MetricCard,
} from '../../ui';

type Provider = 'fmc' | 'scc';
type State =
  | { status: 'loading' }
  | { status: 'ready'; connections: ProviderConnection[]; message?: string }
  | { status: 'error'; message: string; correlationId?: string };

const regions = [
  ['us', 'United States'],
  ['eu', 'Europe'],
  ['apj', 'Asia Pacific / Japan'],
  ['au', 'Australia'],
  ['in', 'India'],
  ['uae', 'UAE'],
  ['fedramp', 'FedRAMP'],
  ['il5', 'IL5'],
] as const;

export function ProviderConnectionsPanel() {
  const [state, setState] = useState<State>({ status: 'loading' });
  const [createOpened, setCreateOpened] = useState(false);
  const loadConnections = useCallback(async (): Promise<ProviderConnection[]> => {
    try {
      const connections = await loadProviderConnections();
      setState({ status: 'ready', connections });
      return connections;
    } catch (error: unknown) {
      setState(toError(error));
      return [];
    }
  }, []);
  useEffect(() => {
    const timer = window.setTimeout(() => void loadConnections(), 0);
    return () => window.clearTimeout(timer);
  }, [loadConnections]);

  if (state.status === 'loading') return <AppLoadingState label="Loading provider connections" />;
  if (state.status === 'error') {
    return <AppErrorState message={state.message} reference={state.correlationId} />;
  }
  const connected = state.connections.filter(
    (connection) => connection.connection_status === 'CONNECTED',
  ).length;
  const active = state.connections.filter((connection) => connection.lifecycle === 'ACTIVE').length;
  const scopes = state.connections.reduce(
    (total, connection) => total + connection.scopes.length,
    0,
  );
  const attention = state.connections.filter(
    (connection) =>
      connection.last_error_message ||
      connection.connection_status === 'FAILED' ||
      connection.compatibility_warning,
  ).length;

  return (
    <Stack gap="lg">
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <MetricCard
          label="Connections"
          value={state.connections.length}
          detail={`${active} enabled for sync`}
          icon={<IconDatabase size={19} />}
        />
        <MetricCard
          label="Healthy"
          value={connected}
          detail="Latest test connected"
          icon={<IconCloudCheck size={19} />}
        />
        <MetricCard
          label="Discovered scopes"
          value={scopes}
          detail="Domains and tenants"
          icon={<IconShieldCheck size={19} />}
        />
        <MetricCard
          label="Needs attention"
          value={attention}
          detail={attention ? 'Review warnings or connection health' : 'No warnings or failures'}
          icon={<IconActivityHeartbeat size={19} />}
        />
      </SimpleGrid>

      <Card>
        <AppSection
          title="Provider connections"
          description="Manage FMC and Security Cloud Control connectivity, synchronization, and production writes."
          actions={
            <Group gap="sm">
              <AppStatusBadge
                value="COUNT"
                label={`${state.connections.length} ${state.connections.length === 1 ? 'connection' : 'connections'}`}
              />
              <Button leftSection={<IconPlus size={16} />} onClick={() => setCreateOpened(true)}>
                Add Connection
              </Button>
            </Group>
          }
        >
          {state.message && <Alert color="green">{state.message}</Alert>}
          <Stack mt="lg" gap="md">
            {state.connections.length === 0 && (
              <AppEmptyState
                title="No provider connections"
                description="Add an FMC or Security Cloud Control connection to begin discovery."
              />
            )}
            {state.connections.map((connection) => (
              <ConnectionCard
                key={connection.id}
                connection={connection}
                onChanged={loadConnections}
              />
            ))}
          </Stack>
        </AppSection>
      </Card>

      <Dialog
        opened={createOpened}
        onClose={() => setCreateOpened(false)}
        title="Add Provider Connection"
        closeButtonProps={{ 'aria-label': 'Close' }}
        classNames={{
          content: 'fm-management-modal',
          header: 'fm-management-modal-header',
          body: 'fm-management-modal-body',
        }}
        size="xl"
        centered
      >
        <ConnectionWizard
          onSaved={() => {
            void loadConnections();
          }}
          onCompleted={() => setCreateOpened(false)}
        />
      </Dialog>
    </Stack>
  );
}

function ConnectionWizard({
  onSaved,
  onCompleted,
}: {
  onSaved: () => void;
  onCompleted?: () => void;
}) {
  const [provider, setProvider] = useState<Provider>('fmc');
  const [guidance, setGuidance] = useState<ProviderGuidance | null>(null);
  const [displayName, setDisplayName] = useState('');
  const [endpoint, setEndpoint] = useState('https://');
  const [region, setRegion] = useState<string | null>('us');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [tlsMode, setTlsMode] = useState<string | null>('SYSTEM');
  const [caCertificate, setCaCertificate] = useState('');
  const [message, setMessage] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void loadProviderGuidance(provider)
      .then(setGuidance)
      .catch(() => setGuidance(null));
  }, [provider]);

  const submit = () => {
    setSaving(true);
    setMessage('');
    const payload =
      provider === 'fmc'
        ? {
            provider_type: provider,
            display_name: displayName,
            base_endpoint: endpoint,
            username,
            password,
            tls_mode: tlsMode,
            ca_certificate: tlsMode === 'CUSTOM_CA' ? caCertificate : undefined,
          }
        : { provider_type: provider, display_name: displayName, region, token };
    void createProviderConnection(payload)
      .then(() => {
        setMessage('Connection saved. Test it, then enable the connection when ready.');
        setDisplayName('');
        onSaved();
        onCompleted?.();
      })
      .catch((error: unknown) => setMessage(errorMessage(error)))
      .finally(() => {
        // Restricted values leave component state immediately after submission completes.
        setPassword('');
        setToken('');
        setCaCertificate('');
        setSaving(false);
      });
  };

  return (
    <form
      onSubmit={(event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        submit();
      }}
    >
      <div className="fm-provider-wizard-intro">
        <ThemeIcon variant="light" color="blue" size="lg">
          <IconKey size={19} />
        </ThemeIcon>
        <div>
          <Text fw={700}>Connect a provider</Text>
          <Text size="sm" c="dimmed">
            Enter the endpoint and a least-privilege credential for the operations you intend to
            allow. The connection remains disabled until it passes a connection test.
          </Text>
        </div>
      </div>
      <SimpleGrid cols={{ base: 1, md: 2 }} mt="md">
        <Select
          label="Provider"
          value={provider}
          onChange={(value) => setProvider((value as Provider | null) ?? 'fmc')}
          data={[
            { value: 'fmc', label: 'Cisco FMC' },
            { value: 'scc', label: 'Cisco Security Cloud Control' },
          ]}
        />
        <TextInput
          label="Display name"
          placeholder={provider === 'fmc' ? 'FMC — Corporate' : 'SCC — US Production'}
          value={displayName}
          onChange={(event) => setDisplayName(event.currentTarget.value)}
          required
        />
        {provider === 'fmc' ? (
          <>
            <TextInput
              label="FMC HTTPS URL"
              value={endpoint}
              onChange={(event) => setEndpoint(event.currentTarget.value)}
              required
            />
            <TextInput
              label="Dedicated API username"
              autoComplete="off"
              value={username}
              onChange={(event) => setUsername(event.currentTarget.value)}
              required
            />
            <TextInput
              label="Password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.currentTarget.value)}
              required
            />
            <Select
              label="TLS trust"
              value={tlsMode}
              onChange={setTlsMode}
              data={[
                { value: 'SYSTEM', label: 'System trust store' },
                { value: 'CUSTOM_CA', label: 'Private CA certificate/bundle' },
              ]}
            />
            {tlsMode === 'CUSTOM_CA' && (
              <Textarea
                label="PEM CA certificate/bundle"
                value={caCertificate}
                onChange={(event) => setCaCertificate(event.currentTarget.value)}
                minRows={5}
                required
              />
            )}
          </>
        ) : (
          <>
            <Select
              label="Cisco region"
              value={region}
              onChange={setRegion}
              data={regions.map(([value, label]) => ({ value, label }))}
            />
            <TextInput
              label="API-only user token"
              type="password"
              autoComplete="new-password"
              value={token}
              onChange={(event) => setToken(event.currentTarget.value)}
              required
            />
          </>
        )}
      </SimpleGrid>
      {guidance && <SetupGuidance guidance={guidance} />}
      {message && (
        <Alert color={message.startsWith('Connection saved') ? 'green' : 'red'} mt="md">
          {message}
        </Alert>
      )}
      <Button
        type="submit"
        mt="md"
        loading={saving}
        disabled={!displayName || (provider === 'fmc' ? !username || !password : !token)}
      >
        Save disabled connection
      </Button>
    </form>
  );
}

function SetupGuidance({ guidance }: { guidance: ProviderGuidance }) {
  return (
    <Alert color="cyan" title={`How to create this credential — ${guidance.title}`} mt="md">
      <Text size="sm" fw={700}>
        Capability target: {guidance.capability_target}
      </Text>
      <ol>
        {guidance.steps.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ol>
      <Text size="sm">{guidance.permission_note}</Text>
      <ul>
        {guidance.official_references.map((reference) => (
          <li key={reference.url}>
            <a href={reference.url} target="_blank" rel="noreferrer">
              {reference.label}
            </a>
          </li>
        ))}
      </ul>
    </Alert>
  );
}

function ConnectionCard({
  connection,
  onChanged,
}: {
  connection: ProviderConnection;
  onChanged: () => Promise<ProviderConnection[]>;
}) {
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [replacement, setReplacement] = useState('');
  const [replacementUsername, setReplacementUsername] = useState(
    connection.credential_username ?? '',
  );
  const [replacementCa, setReplacementCa] = useState('');
  const [newName, setNewName] = useState(connection.display_name);
  const [newEndpoint, setNewEndpoint] = useState(connection.base_endpoint ?? '');
  const [newRegion, setNewRegion] = useState<string | null>(connection.region);
  const [newTlsMode, setNewTlsMode] = useState<string | null>(connection.tls_mode);
  const [newSyncInterval, setNewSyncInterval] = useState(String(connection.sync_interval_minutes));
  const [newApplicationsSyncInterval, setNewApplicationsSyncInterval] = useState(
    String(connection.applications_sync_interval_minutes),
  );
  const [newDeploymentScheduleEnabled, setNewDeploymentScheduleEnabled] = useState(
    connection.deployment_schedule_enabled,
  );
  const [editing, setEditing] = useState(false);

  const run = (operation: () => Promise<unknown>, success: string) => {
    setBusy(true);
    setMessage('');
    void operation()
      .then(() => {
        setMessage(success);
        void onChanged();
      })
      .catch((error: unknown) => setMessage(errorMessage(error)))
      .finally(() => setBusy(false));
  };
  const rotate = () => {
    const values =
      connection.provider_type === 'fmc'
        ? {
            username: replacementUsername,
            password: replacement,
            ca_certificate: replacementCa || undefined,
          }
        : { token: replacement };
    run(
      () => rotateProviderCredential(connection, values),
      'Credential replaced; retest before enabling.',
    );
    setReplacement('');
    setReplacementCa('');
  };
  const saveConfiguration = () => {
    const values = {
      display_name: newName,
      sync_interval_minutes: Number(newSyncInterval),
      applications_sync_interval_minutes: Number(newApplicationsSyncInterval),
      deployment_schedule_enabled: newDeploymentScheduleEnabled,
      ...(connection.provider_type === 'fmc'
        ? { base_endpoint: newEndpoint, tls_mode: newTlsMode }
        : { region: newRegion }),
    };
    run(
      () => updateProviderConnection(connection, values),
      'Connection updated; retest if needed.',
    );
  };
  const configurationChanged =
    newName !== connection.display_name ||
    Number(newSyncInterval) !== connection.sync_interval_minutes ||
    Number(newApplicationsSyncInterval) !== connection.applications_sync_interval_minutes ||
    newDeploymentScheduleEnabled !== connection.deployment_schedule_enabled ||
    (connection.provider_type === 'fmc'
      ? newEndpoint !== connection.base_endpoint || newTlsMode !== connection.tls_mode
      : newRegion !== connection.region);
  const canEnableWrites =
    connection.lifecycle === 'ACTIVE' && connection.connection_status === 'CONNECTED';
  const toggleWrites = () => {
    const confirmation =
      `Enable production configuration writes for ${connection.display_name} (${connection.provider_type.toUpperCase()})? ` +
      (connection.compatibility_warning ? `${connection.compatibility_warning} ` : '') +
      'All writes still require a reviewed ChangeSet and backend authorization. This does not deploy changes.';
    if (!connection.write_enabled && !window.confirm(confirmation)) return;
    run(
      () => setProviderConnectionWriteGate(connection, !connection.write_enabled),
      connection.write_enabled
        ? 'Provider writes disabled.'
        : 'Production provider writes enabled.',
    );
  };
  const retire = () => {
    if (!window.confirm('Retire this connection? Historical inventory and audit records remain.'))
      return;
    run(() => setProviderConnectionLifecycle(connection, 'RETIRED'), 'Connection retired.');
  };
  const sync = async (mode: 'FULL' | 'NON_APPLICATIONS' = 'FULL') => {
    setBusy(true);
    setMessage('Sync queued. Waiting for the worker to start…');
    try {
      await requestProviderSync(connection.id, mode);
      for (let attempt = 0; attempt < 120; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1000));
        const connections = await onChanged();
        const current = connections.find((item) => item.id === connection.id);
        const completed = current?.sync_status === 'COMPLETED';
        const failed = current?.sync_status === 'FAILED';
        if (completed) {
          setMessage(`Sync completed at ${formatDate(current?.last_successful_sync ?? null)}.`);
          return;
        }
        if (failed || (mode === 'FULL' && current?.last_error_code)) {
          setMessage(
            `Sync failed: ${humanize(current?.last_error_code ?? 'PROVIDER_SYNC_FAILED')}.`,
          );
          return;
        }
        setMessage(
          current?.sync_status === 'RUNNING'
            ? 'Sync is running. Refreshing provider state…'
            : 'Sync queued. Waiting for the worker to start…',
        );
      }
      setMessage('Sync is still running. The status badge will update when it finishes.');
    } catch (error: unknown) {
      setMessage(
        error instanceof ApiError
          ? `Sync could not be queued: ${error.message}`
          : 'Sync could not be queued.',
      );
    } finally {
      setBusy(false);
    }
  };
  const forceDeploy = async () => {
    if (!window.confirm(`Deploy all pending staged changes for ${connection.display_name} now?`)) return;
    setBusy(true);
    setMessage('Deployment batch queued. Waiting for the worker…');
    try {
      const result = await forceProviderDeployment(connection.id);
      if (!('id' in result)) {
        setMessage('No pending staged changes for this connector.');
        return;
      }
      for (let attempt = 0; attempt < 120; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1000));
        const deployments = await loadDeployments();
        const current = deployments.find((item) => item.id === result.id);
        const state = current?.state ?? 'READY';
        setMessage(`Deployment ${state.toLowerCase().replaceAll('_', ' ')}…`);
        if (['DEPLOYED', 'FAILED', 'PARTIAL', 'UNKNOWN', 'RECONCILIATION_REQUIRED'].includes(state)) {
          setMessage(
            state === 'DEPLOYED'
              ? 'Deployment completed successfully.'
              : `Deployment ${state.toLowerCase().replaceAll('_', ' ')}.`,
          );
          return;
        }
      }
      setMessage('Deployment is still running. The Deployments view will continue to update.');
    } catch (error: unknown) {
      setMessage(errorMessage(error));
    } finally {
      setBusy(false);
      void onChanged();
    }
  };

  return (
    <Card className="fm-provider-card">
      <div className="fm-provider-card-head">
        <Group align="center" gap="sm" wrap="nowrap">
          <ThemeIcon className="fm-provider-mark" variant="light" color="blue" size="xl">
            <IconDatabase size={21} />
          </ThemeIcon>
          <div className="fm-provider-title">
            <Group gap="xs">
              <AppProviderBadge provider={connection.provider_type} />
              <Text fw={700} size="lg">
                {connection.display_name}
              </Text>
            </Group>
            <Text size="xs" c="dimmed">
              {connection.provider_version ?? 'Version not discovered'} · Real provider
            </Text>
          </div>
        </Group>
        <Group gap="xs" className="fm-provider-statuses">
          <AppStatusBadge value={connection.lifecycle} />
          <AppStatusBadge value={connection.connection_status} />
          <AppStatusBadge
            value={connection.sync_status ?? 'NEVER_SYNCED'}
            label={connection.sync_status ? humanize(connection.sync_status) : 'Never synced'}
          />
          {connection.compatibility_warning && (
            <AppStatusBadge value="WARNING" label="Version untested" />
          )}
          <AppStatusBadge
            value={connection.write_enabled ? 'WRITE_ENABLED' : 'READ_ONLY'}
            label={connection.write_enabled ? 'Production writes enabled' : 'Read only'}
          />
        </Group>
      </div>

      <div className="fm-provider-facts">
        <ProviderFact
          label="Endpoint / region"
          value={connection.region ?? connection.base_endpoint ?? 'Not configured'}
        />
        <ProviderFact
          label="Last successful test"
          value={formatDate(connection.last_successful_connection)}
        />
        <ProviderFact
          label="Last successful sync"
          value={formatDate(connection.last_successful_sync)}
        />
        <ProviderFact
          label="Sync schedule"
          value={`Every ${connection.sync_interval_minutes} minutes`}
        />
        <ProviderFact
          label="Application catalog schedule"
          value={`Every ${connection.applications_sync_interval_minutes} minutes`}
        />
        <ProviderFact
          label="Deployment schedule"
          value={connection.deployment_schedule_enabled ? 'Every 15 minutes' : 'Disabled'}
        />
      </div>
      {(connection.last_error_message || connection.last_error_code) && (
        <Alert color="red" mt="sm">
          {connection.last_error_message ?? humanize(connection.last_error_code ?? 'SYNC_FAILED')}{' '}
          {connection.last_error_correlation_id
            ? `Reference: ${connection.last_error_correlation_id}`
            : ''}
        </Alert>
      )}
      {connection.compatibility_warning && (
        <Alert color="yellow" mt="sm" title="Untested provider version">
          {connection.compatibility_warning}
        </Alert>
      )}
      <div className="fm-provider-discovery">
        <ProviderTokens
          label="Domains and tenants"
          values={connection.scopes.map((scope) => scope.name)}
          empty="No scopes discovered"
        />
      </div>

      <div className="fm-provider-actions">
        <Group gap="xs" wrap="wrap">
          <ActionButton
            intent="secondary"
            leftSection={<IconActivityHeartbeat size={14} />}
            loading={busy}
            onClick={() =>
              run(() => testProviderConnection(connection.id), 'Connection test completed.')
            }
          >
            Test connection
          </ActionButton>
          <ActionButton
            intent={connection.write_enabled ? 'quiet-danger' : 'secondary'}
            disabled={!connection.write_enabled && !canEnableWrites}
            loading={busy}
            onClick={toggleWrites}
          >
            {connection.write_enabled ? 'Return to read-only' : 'Enable production writes'}
          </ActionButton>
          {connection.lifecycle === 'ACTIVE' ? (
            <ActionButton
              intent="quiet-danger"
              onClick={() =>
                run(
                  () => setProviderConnectionLifecycle(connection, 'DISABLED'),
                  'Connection disabled.',
                )
              }
            >
              Disable
            </ActionButton>
          ) : connection.lifecycle !== 'RETIRED' ? (
            <ActionButton
              intent="success"
              disabled={connection.connection_status !== 'CONNECTED'}
              onClick={() =>
                run(
                  () => setProviderConnectionLifecycle(connection, 'ACTIVE'),
                  'Connection enabled.',
                )
              }
            >
              Enable
            </ActionButton>
          ) : null}
          <ActionButton
            intent="secondary"
            leftSection={<IconRefresh size={14} />}
            disabled={connection.lifecycle !== 'ACTIVE'}
            loading={busy}
            onClick={() => {
              void sync('FULL');
            }}
          >
            Sync all
          </ActionButton>
          <ActionButton
            intent="secondary"
            leftSection={<IconRefresh size={14} />}
            disabled={connection.lifecycle !== 'ACTIVE'}
            loading={busy}
            onClick={() => void sync('NON_APPLICATIONS')}
          >
            Sync without applications
          </ActionButton>
          <ActionButton
            intent="secondary"
            disabled={connection.lifecycle !== 'ACTIVE' || !connection.write_enabled}
            loading={busy}
            onClick={() => void forceDeploy()}
          >
            Deploy pending changes now
          </ActionButton>
        </Group>
        <Group gap="xs" wrap="wrap">
          {connection.lifecycle !== 'RETIRED' && (
            <ActionButton
              intent="quiet"
              leftSection={<IconSettings size={14} />}
              onClick={() => setEditing((value) => !value)}
            >
              {editing ? 'Close settings' : 'Edit connection'}
            </ActionButton>
          )}
          {connection.lifecycle !== 'RETIRED' && (
            <ActionButton intent="danger" onClick={retire}>
              Retire
            </ActionButton>
          )}
        </Group>
      </div>
      {connection.lifecycle !== 'RETIRED' && editing && (
        <SimpleGrid className="fm-provider-settings" cols={{ base: 1, md: 2 }}>
          <div className="fm-provider-settings-panel">
            <Text fw={700}>Connection settings</Text>
            <Text size="xs" c="dimmed" mb="sm">
              Update discovery and synchronization configuration.
            </Text>
            <TextInput
              label="Display name"
              value={newName}
              onChange={(event) => setNewName(event.currentTarget.value)}
            />
            <TextInput
              label="Application catalog sync interval (minutes)"
              description="Use a longer cadence for the provider application catalog. Minimum 60 minutes."
              type="number"
              min={60}
              max={43200}
              value={newApplicationsSyncInterval}
              onChange={(event) => setNewApplicationsSyncInterval(event.currentTarget.value)}
            />
            {connection.provider_type === 'fmc' ? (
              <>
                <TextInput
                  label="FMC HTTPS URL"
                  value={newEndpoint}
                  onChange={(event) => setNewEndpoint(event.currentTarget.value)}
                />
                <Select
                  label="TLS trust"
                  value={newTlsMode}
                  onChange={setNewTlsMode}
                  data={[
                    { value: 'SYSTEM', label: 'System trust store' },
                    { value: 'CUSTOM_CA', label: 'Private CA certificate/bundle' },
                  ]}
                />
              </>
            ) : (
              <Select
                label="Cisco region"
                value={newRegion}
                onChange={setNewRegion}
                data={regions.map(([value, label]) => ({ value, label }))}
              />
            )}
            <TextInput
              label="Sync interval (minutes)"
              type="number"
              min={5}
              max={10080}
              value={newSyncInterval}
              onChange={(event) => setNewSyncInterval(event.currentTarget.value)}
            />
            <Button
              variant="light"
              mt="sm"
              onClick={() => setNewDeploymentScheduleEnabled((value) => !value)}
            >
              Automatic deployment: {newDeploymentScheduleEnabled ? 'enabled' : 'disabled'}
            </Button>
            <Button mt="sm" disabled={!configurationChanged} onClick={saveConfiguration}>
              Save configuration
            </Button>
          </div>
          <div className="fm-provider-settings-panel">
            <Text fw={700}>Credential rotation</Text>
            <Text size="xs" c="dimmed" mb="sm">
              Replace the stored secret, then test the connection again.
            </Text>
            {connection.provider_type === 'fmc' && (
              <TextInput
                label="Username"
                value={replacementUsername}
                onChange={(event) => setReplacementUsername(event.currentTarget.value)}
              />
            )}
            <TextInput
              label={connection.provider_type === 'fmc' ? 'New password' : 'New API token'}
              type="password"
              autoComplete="new-password"
              value={replacement}
              onChange={(event) => setReplacement(event.currentTarget.value)}
            />
            {connection.provider_type === 'fmc' && (
              <Textarea
                label="Replacement PEM CA certificate/bundle (optional)"
                value={replacementCa}
                onChange={(event) => setReplacementCa(event.currentTarget.value)}
                minRows={3}
              />
            )}
            <Button mt="sm" disabled={!replacement} onClick={rotate}>
              Replace credential
            </Button>
          </div>
        </SimpleGrid>
      )}
      {message && (
        <Alert color={message.includes('failed') ? 'red' : 'blue'} mt="md">
          {message}
        </Alert>
      )}
    </Card>
  );
}

function ProviderFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="fm-provider-fact">
      <Text size="10px" c="dimmed" tt="uppercase" fw={700} lts=".06em">
        {label}
      </Text>
      <Text size="sm" fw={650} mt={5} lineClamp={2} title={value}>
        {value}
      </Text>
    </div>
  );
}

function ProviderTokens({
  label,
  values,
  empty,
}: {
  label: string;
  values: string[];
  empty: string;
}) {
  return (
    <div>
      <Text size="10px" c="dimmed" tt="uppercase" fw={700} lts=".06em" mb={7}>
        {label}
      </Text>
      <div className="fm-provider-tokens">
        {values.length ? (
          values.map((value) => (
            <span className="fm-provider-token" key={value}>
              {value}
            </span>
          ))
        ) : (
          <Text size="xs" c="dimmed">
            {empty}
          </Text>
        )}
      </div>
    </div>
  );
}

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Never';
}

function humanize(value: string) {
  return value
    .toLowerCase()
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function errorMessage(error: unknown) {
  return error instanceof ApiError
    ? `${error.message} Reference: ${error.correlationId}`
    : error instanceof Error
      ? error.message
      : 'Request failed.';
}

function toError(error: unknown): State {
  return error instanceof ApiError
    ? { status: 'error', message: error.message, correlationId: error.correlationId }
    : { status: 'error', message: 'Provider connection administration is unavailable.' };
}
