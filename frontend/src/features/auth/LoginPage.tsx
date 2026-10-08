// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';
import { IconArrowUpRight } from '@tabler/icons-react';

import {
  ApiError,
  createInitialSetup,
  loadAdministratorContact,
  loadInitialSetupDraft,
  loadInitialSetupStatus,
  loadOidcLoginProviders,
  testInitialSetup,
  type OidcLoginProvider,
} from '../../api/client';
import {
  AppAlert,
  AppButton,
  AppDivider,
  AppGroup,
  AppSelect,
  AppStack,
  AppText,
  AppTextInput,
  AppTitle,
  FirewallPolicyWordmark,
} from '../../ui';

export function LoginPage({ initialError }: { initialError?: string } = {}) {
  const [providers, setProviders] = useState<OidcLoginProvider[]>([]);
  const [administratorEmail, setAdministratorEmail] = useState<string | null>(null);
  const [setupAvailable, setSetupAvailable] = useState(false);
  const [recoverySetup, setRecoverySetup] = useState(false);
  const [error, setError] = useState<string | undefined>(initialError);

  useEffect(() => {
    void loadOidcLoginProviders()
      .then(setProviders)
      .catch((caught: unknown) => {
        setError(
          caught instanceof ApiError
            ? `${caught.message} Reference: ${caught.correlationId}`
            : 'Unable to load configured identity providers.',
        );
      });
  }, []);

  useEffect(() => {
    const recoveryCode =
      new URLSearchParams(window.location.search).get('setup_recovery') ?? undefined;
    void loadInitialSetupStatus(recoveryCode)
      .then(({ available, recovery }) => {
        setSetupAvailable(available);
        setRecoverySetup(recovery);
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    void loadAdministratorContact()
      .then(({ email }) => setAdministratorEmail(email))
      .catch(() => undefined);
  }, []);

  return (
    <main className="fm-login-shell">
      <div
        className={`fm-login-grid fm-login-auth-visual ${setupAvailable || recoverySetup ? 'fm-login-setup-layout' : ''}`}
      >
        <section className="fm-login-panel" aria-labelledby="login-title">
          <div className="fm-login-panel-inner">
            <div className="fm-login-brand fm-login-panel-brand">
              <FirewallPolicyWordmark />
            </div>
            {error ? (
              <>
                <AppTitle id="login-title" order={2}>
                  Sign-in unavailable.
                </AppTitle>
                <AppText c="dimmed" mt={7} maw={410}>
                  The identity provider catalog could not be loaded.
                </AppText>
                <AppAlert color="red" mt="xl" title="Sign-in options unavailable">
                  {error}
                </AppAlert>
              </>
            ) : providers.length === 0 && (setupAvailable || recoverySetup) ? (
              <InitialSetupPanel
                recovery={recoverySetup}
                onComplete={() => window.location.reload()}
              />
            ) : providers.length === 0 ? (
              <>
                <AppTitle id="login-title" order={2}>
                  Welcome back.
                </AppTitle>
                <AppText c="dimmed" mt={7} maw={410}>
                  Sign in with your organization account to manage firewall policies, rules, and
                  objects.
                </AppText>
                <AppDivider my="xl" label="CONTINUE WITH" labelPosition="left" />
                <AppAlert
                  className="fm-login-empty-alert"
                  color="yellow"
                  title="No identity provider configured"
                >
                  Ask an administrator to configure an OIDC provider before signing in.
                </AppAlert>
              </>
            ) : (
              <>
                <AppTitle id="login-title" order={2}>
                  Welcome back.
                </AppTitle>
                <AppText c="dimmed" mt={7} maw={410}>
                  Sign in with your organization account to manage firewall policies, rules, and
                  objects.
                </AppText>
                <AppDivider my="xl" label="CONTINUE WITH" labelPosition="left" />
                <AppStack gap="sm">
                  {providers.map((provider) => (
                    <ProviderButton key={provider.provider_id} provider={provider} />
                  ))}
                </AppStack>
              </>
            )}

            <AppGroup className="fm-login-footer" justify="space-between" mt="xl">
              <AppText size="xs" c="dimmed">
                Need access?{' '}
                {administratorEmail ? (
                  <a href={`mailto:${administratorEmail}`}>Contact an administrator.</a>
                ) : (
                  'Contact an administrator.'
                )}
              </AppText>
            </AppGroup>
          </div>
        </section>
        <aside className="fm-login-visual" aria-label="Protected network visualization">
          <div className="fm-login-visual-caption">
            <AppText size="xs" fw={750} tt="uppercase" lts=".12em">
              Delegated policy management
            </AppText>
            <AppText size="sm" c="dimmed" mt={4}>
              Shared firewalls. Delegated access.
            </AppText>
          </div>
        </aside>
      </div>
    </main>
  );
}

function InitialSetupPanel({
  recovery,
  onComplete,
}: {
  recovery: boolean;
  onComplete: () => void;
}) {
  const query = new URLSearchParams(window.location.search);
  const recoveryCode = query.get('setup_recovery') ?? undefined;
  const setupTestId = query.get('setup_test_id') ?? undefined;
  const [values, setValues] = useState({
    organization_name: '',
    admin_display_name: '',
    admin_email: '',
    admin_issuer: '',
    provider_id: 'primary',
    provider_kind: 'generic',
    provider_display_name: '',
    provider_issuer_url: '',
    provider_client_id: '',
    provider_client_secret: '',
    recovery_code: recoveryCode,
    setup_test_id: setupTestId,
  });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [tested, setTested] = useState(
    query.get('setup_test') === 'success' && Boolean(setupTestId),
  );
  const [error, setError] = useState('');
  useEffect(() => {
    if (!setupTestId) return;
    void loadInitialSetupDraft(setupTestId)
      .then((draft) =>
        setValues((current) => ({
          ...current,
          ...draft,
          recovery_code: recoveryCode,
          setup_test_id: setupTestId,
        })),
      )
      .catch((caught: unknown) =>
        setError(
          caught instanceof ApiError
            ? formatSetupError(caught)
            : 'Unable to restore the setup draft.',
        ),
      );
  }, [recoveryCode, setupTestId]);
  const update = (key: string, value: string) => {
    setTested(false);
    setError('');
    setValues((current) => ({
      ...current,
      [key]: value,
      ...(key === 'provider_display_name' ? { provider_id: setupProviderSlug(value) } : {}),
    }));
  };
  const test = () => {
    setTesting(true);
    setError('');
    const payload = recovery ? { ...values, organization_name: undefined } : values;
    void testInitialSetup(payload)
      .then(({ login_url }) => {
        window.location.assign(login_url);
      })
      .catch((caught: unknown) =>
        setError(
          caught instanceof ApiError
            ? formatSetupError(caught)
            : 'Unable to test the provider configuration.',
        ),
      )
      .finally(() => setTesting(false));
  };
  const save = () => {
    if (!tested) {
      setError('Test the provider configuration successfully before saving setup.');
      return;
    }
    setSaving(true);
    setError('');
    const payload = recovery ? { ...values, organization_name: undefined } : values;
    void createInitialSetup(payload)
      .then(onComplete)
      .catch((caught: unknown) => {
        if (!(caught instanceof ApiError)) {
          setError('Unable to complete initial setup.');
          return;
        }
        const fields = caught.details.fields;
        const reason = caught.details.reason;
        const detail =
          Array.isArray(fields) && fields.length > 0
            ? `Check these fields: ${fields.join(', ')}.`
            : typeof reason === 'string' && reason
              ? reason
              : '';
        setError(detail ? `${caught.message} ${detail}` : caught.message);
      })
      .finally(() => setSaving(false));
  };
  return (
    <div className="fm-initial-setup">
      <AppText className="fm-setup-kicker" size="xs" fw={800}>
        {recovery ? 'RECOVERY SETUP' : 'INITIAL SETUP'}
      </AppText>
      <AppTitle id="login-title" order={2}>
        {recovery ? 'Restore administrator access.' : 'Configure your deployment.'}
      </AppTitle>
      <AppText c="dimmed" mt={7}>
        {recovery
          ? 'Create a new administrator identity and reconnect an OIDC provider.'
          : 'Create the first organization, administrator, and sign-in provider.'}
      </AppText>
      {error && (
        <AppAlert className="fm-login-error-alert" color="red" mt="md">
          {error}
        </AppAlert>
      )}
      {tested && (
        <AppAlert className="fm-login-success-alert" color="teal" mt="md">
          Provider discovery succeeded. You can now save setup.
        </AppAlert>
      )}
      <AppStack gap="sm" mt="xl">
        {!recovery && (
          <>
            <AppText size="xs" fw={800} tt="uppercase" lts=".1em">
              Organization
            </AppText>
            <AppTextInput
              label="Organization name"
              value={values.organization_name}
              onChange={(event) => update('organization_name', event.currentTarget.value)}
            />
          </>
        )}
        <AppTextInput
          label="Administrator display name"
          value={values.admin_display_name}
          onChange={(event) => update('admin_display_name', event.currentTarget.value)}
        />
        <AppTextInput
          label="Administrator email"
          type="email"
          value={values.admin_email}
          onChange={(event) => update('admin_email', event.currentTarget.value)}
        />
        <AppText size="xs" fw={800} tt="uppercase" lts=".1em" mt="sm">
          Identity provider
        </AppText>
        <AppTextInput
          label="Generated provider ID"
          description="Created from the provider display name and used in the callback URL."
          value={values.provider_id}
          readOnly
        />
        <AppSelect
          label="Provider type"
          data={[
            { value: 'entra', label: 'Microsoft Entra ID' },
            { value: 'duo', label: 'Cisco Duo SSO' },
            { value: 'generic', label: 'Generic OIDC' },
          ]}
          value={values.provider_kind}
          onChange={(value) => update('provider_kind', value ?? 'generic')}
        />
        <AppTextInput
          label="Provider display name"
          value={values.provider_display_name}
          onChange={(event) => update('provider_display_name', event.currentTarget.value)}
        />
        <AppTextInput
          label="Issuer URL"
          placeholder="https://issuer.example.com"
          value={values.provider_issuer_url}
          onChange={(event) => {
            update('provider_issuer_url', event.currentTarget.value);
            update('admin_issuer', event.currentTarget.value);
          }}
        />
        <AppTextInput
          label="Client ID"
          value={values.provider_client_id}
          onChange={(event) => update('provider_client_id', event.currentTarget.value)}
        />
        <AppTextInput
          label="Client secret"
          type="password"
          value={values.provider_client_secret}
          onChange={(event) => update('provider_client_secret', event.currentTarget.value)}
        />
        <AppButton
          className="fm-login-test-button"
          variant="light"
          loading={testing}
          onClick={test}
        >
          Test configuration
        </AppButton>
        <AppButton
          className="fm-login-save-button"
          loading={saving}
          disabled={!tested}
          onClick={save}
        >
          Complete initial setup
        </AppButton>
      </AppStack>
    </div>
  );
}

function setupProviderSlug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 80);
}

function formatSetupError(error: ApiError): string {
  const fields = error.details.fields;
  const reason = error.details.reason;
  if (Array.isArray(fields) && fields.length > 0)
    return `${error.message} Check these fields: ${fields.join(', ')}.`;
  if (typeof reason === 'string' && reason) return `${error.message} ${reason}`;
  return error.message;
}

function ProviderButton({ provider }: { provider: OidcLoginProvider }) {
  return (
    <AppButton
      className="fm-login-provider"
      component="a"
      href={`/api/v1/auth/${encodeURIComponent(provider.provider_id)}/login`}
      fullWidth
      justify="space-between"
      rightSection={<IconArrowUpRight size={17} stroke={1.8} />}
      leftSection={
        <span className="fm-provider-initial">
          {provider.display_name.slice(0, 1).toUpperCase()}
        </span>
      }
    >
      <span className="fm-provider-label">
        <span>{provider.display_name}</span>
        <small>{provider.kind.toUpperCase()} identity provider</small>
      </span>
    </AppButton>
  );
}
