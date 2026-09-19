import { useCallback, useEffect, useState } from 'react';

import {
  ApiError,
  createProviderConnection,
  loadProviderConnections,
  loadProviderGuidance,
  requestProviderSync,
  rotateProviderCredential,
  setProviderConnectionLifecycle,
  testProviderConnection,
  updateProviderConnection,
  type ProviderConnection,
  type ProviderGuidance,
} from '../../api/client';
import {
  AppAlert as Alert,
  AppBadge as Badge,
  AppButton as Button,
  AppCard as Card,
  AppErrorState,
  AppGroup as Group,
  AppLoadingState,
  AppSelect as Select,
  AppSimpleGrid as SimpleGrid,
  AppStack as Stack,
  AppText as Text,
  AppTextarea as Textarea,
  AppTextInput as TextInput,
  AppTitle as Title,
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
  const load = useCallback(() => {
    void loadProviderConnections()
      .then((connections) => setState({ status: 'ready', connections }))
      .catch((error: unknown) => setState(toError(error)));
  }, []);
  useEffect(load, [load]);

  if (state.status === 'loading') return <AppLoadingState label="Loading provider connections" />;
  if (state.status === 'error') {
    return <AppErrorState message={state.message} reference={state.correlationId} />;
  }
  return (
    <section aria-labelledby="provider-connections-heading">
      <Title id="provider-connections-heading" order={3} mb="sm">
        Provider connections
      </Title>
      <Alert color="blue" mb="md">
        Real FMC and SCC connections are structurally read-only. Credentials with broader provider
        roles do not enable configuration writes.
      </Alert>
      {state.message && <Alert color="green">{state.message}</Alert>}
      <ConnectionWizard onSaved={load} />
      <Stack mt="lg">
        {state.connections.length === 0 && (
          <Text c="dimmed">No real providers are configured. Local mocks continue to operate.</Text>
        )}
        {state.connections.map((connection) => (
          <ConnectionCard key={connection.id} connection={connection} onChanged={load} />
        ))}
      </Stack>
    </section>
  );
}

function ConnectionWizard({ onSaved }: { onSaved: () => void }) {
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
        setMessage('Connection saved disabled. Test it before enabling synchronization.');
        setDisplayName('');
        onSaved();
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
    <Card
      withBorder
      component="form"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <Title order={4}>Add connection</Title>
      <Text size="sm" c="dimmed">
        1. Choose provider · 2. Connection details · 3. Credential · 4. TLS/region · 5. Least
        privilege · 6. Save, test, then enable
      </Text>
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
    </Card>
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
  onChanged: () => void;
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

  const run = (operation: () => Promise<unknown>, success: string) => {
    setBusy(true);
    setMessage('');
    void operation()
      .then(() => {
        setMessage(success);
        onChanged();
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
    (connection.provider_type === 'fmc'
      ? newEndpoint !== connection.base_endpoint || newTlsMode !== connection.tls_mode
      : newRegion !== connection.region);
  const retire = () => {
    if (!window.confirm('Retire this connection? Historical inventory and audit records remain.'))
      return;
    run(() => setProviderConnectionLifecycle(connection, 'RETIRED'), 'Connection retired.');
  };

  return (
    <Card withBorder>
      <Group justify="space-between" align="start">
        <div>
          <Title order={4}>{connection.display_name}</Title>
          <Text size="sm" c="dimmed">
            {connection.provider_type.toUpperCase()} ·{' '}
            {connection.provider_version ?? 'Version not discovered'} · evidence: real · writable:
            false
          </Text>
        </div>
        <Group>
          <Badge>{connection.lifecycle}</Badge>
          <Badge color={statusColor(connection.connection_status)}>
            {connection.connection_status.replaceAll('_', ' ')}
          </Badge>
        </Group>
      </Group>
      <SimpleGrid cols={{ base: 1, md: 3 }} mt="md">
        <Text size="sm">
          <b>Endpoint/region:</b> {connection.region ?? connection.base_endpoint}
        </Text>
        <Text size="sm">
          <b>Last successful test:</b> {formatDate(connection.last_successful_connection)}
        </Text>
        <Text size="sm">
          <b>Last successful sync:</b> {formatDate(connection.last_successful_sync)}
        </Text>
        <Text size="sm">
          <b>Credential:</b> configured{' '}
          {connection.credential_username ? `for ${connection.credential_username}` : ''}; updated{' '}
          {formatDate(connection.credential_updated_at)}
        </Text>
        <Text size="sm">
          <b>Sync:</b> {connection.sync_status ?? 'Never synchronized'}
        </Text>
        <Text size="sm">
          <b>TLS:</b> {connection.tls_mode}
        </Text>
      </SimpleGrid>
      {connection.last_error_message && (
        <Alert color="red" mt="sm">
          {connection.last_error_message}{' '}
          {connection.last_error_correlation_id
            ? `Reference: ${connection.last_error_correlation_id}`
            : ''}
        </Alert>
      )}
      {Object.keys(connection.certificate_info).length > 0 && (
        <Text size="sm" mt="sm">
          Certificate: {connection.certificate_info.subject} · issuer{' '}
          {connection.certificate_info.issuer} · SHA-256{' '}
          {connection.certificate_info.sha256_fingerprint} · valid{' '}
          {connection.certificate_info.not_valid_before} to{' '}
          {connection.certificate_info.not_valid_after}
        </Text>
      )}
      <Text size="sm" mt="sm">
        <b>Domains/tenants:</b>{' '}
        {connection.scopes.map((scope) => `${scope.name} (${scope.scope_type})`).join(', ') ||
          'None discovered'}
      </Text>
      <Text size="sm">
        <b>Tested reads:</b>{' '}
        {connection.capability_evidence
          .filter((item) => item.evidence_level === 'TESTED')
          .map((item) => item.capability)
          .join(', ') || 'None'}
      </Text>
      <Group mt="md">
        <Button
          variant="outline"
          loading={busy}
          onClick={() =>
            run(() => testProviderConnection(connection.id), 'Connection test completed.')
          }
        >
          Test connection
        </Button>
        {connection.lifecycle === 'ACTIVE' ? (
          <Button
            variant="outline"
            onClick={() =>
              run(
                () => setProviderConnectionLifecycle(connection, 'DISABLED'),
                'Connection disabled.',
              )
            }
          >
            Disable
          </Button>
        ) : connection.lifecycle !== 'RETIRED' ? (
          <Button
            disabled={connection.connection_status !== 'CONNECTED'}
            onClick={() =>
              run(() => setProviderConnectionLifecycle(connection, 'ACTIVE'), 'Connection enabled.')
            }
          >
            Enable
          </Button>
        ) : null}
        <Button
          variant="outline"
          disabled={connection.lifecycle !== 'ACTIVE'}
          onClick={() => run(() => requestProviderSync(connection.id), 'Read-only sync queued.')}
        >
          Sync now
        </Button>
        {connection.lifecycle !== 'RETIRED' && (
          <Button color="red" variant="outline" onClick={retire}>
            Retire
          </Button>
        )}
      </Group>
      {connection.lifecycle !== 'RETIRED' && (
        <SimpleGrid cols={{ base: 1, md: 2 }} mt="md">
          <Card withBorder>
            <Text fw={700}>Edit non-secret configuration</Text>
            <TextInput
              label="Display name"
              value={newName}
              onChange={(event) => setNewName(event.currentTarget.value)}
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
            <Button size="xs" mt="sm" disabled={!configurationChanged} onClick={saveConfiguration}>
              Save configuration
            </Button>
          </Card>
          <Card withBorder>
            <Text fw={700}>Update credentials</Text>
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
            <Button size="xs" mt="sm" disabled={!replacement} onClick={rotate}>
              Replace credential
            </Button>
          </Card>
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

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Never';
}
function statusColor(value: string) {
  return value === 'CONNECTED' ? 'green' : value === 'NEVER_TESTED' ? 'gray' : 'red';
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
