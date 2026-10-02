import { useEffect, useState } from 'react';
import { IconArrowUpRight, IconCheck, IconLock, IconShieldLock } from '@tabler/icons-react';

import { ApiError, loadOidcLoginProviders, type OidcLoginProvider } from '../../api/client';
import {
  AppAlert,
  AppButton,
  AppDivider,
  AppGroup,
  AppStack,
  AppText,
  AppThemeIcon,
  AppTitle,
} from '../../ui';

export function LoginPage({ initialError }: { initialError?: string } = {}) {
  const [providers, setProviders] = useState<OidcLoginProvider[]>([]);
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

  return (
    <main className="fm-login-shell">
      <div className="fm-login-grid fm-login-auth-visual">
        <section className="fm-login-panel" aria-labelledby="login-title">
          <div className="fm-login-panel-inner">
            <div className="fm-login-brand fm-login-panel-brand">
              <div className="fm-brand-mark fm-login-brand-mark"><IconShieldLock size={22} stroke={1.8} /></div>
              <AppText fw={750} size="sm" lts=".02em">FIREWALL MANAGER</AppText>
            </div>
            <div className="fm-login-panel-heading">
              <div className="fm-login-panel-icon"><IconLock size={19} stroke={1.8} /></div>
              <AppText size="xs" fw={750} c="dimmed" tt="uppercase" lts=".12em">Authorized access</AppText>
            </div>
            <AppTitle id="login-title" order={2}>Welcome back.</AppTitle>
            <AppText c="dimmed" mt={7} maw={410}>Sign in with your organization account to access the firewall control plane.</AppText>

            <AppDivider my="xl" label="CONTINUE WITH" labelPosition="left" />

            {error && <AppAlert color="red" mb="md" title="Sign-in options unavailable">{error}</AppAlert>}
            {!error && providers.length === 0 && (
              <AppAlert color="yellow" mb="md" title="No identity provider configured">Ask an administrator to configure an OIDC provider before signing in.</AppAlert>
            )}
            <AppStack gap="sm">
              {providers.map((provider) => <ProviderButton key={provider.provider_id} provider={provider} />)}
            </AppStack>

            <div className="fm-login-security-note">
              <AppThemeIcon size={28} radius="xl" variant="light" color="teal"><IconCheck size={15} /></AppThemeIcon>
              <div>
                <AppText size="sm" fw={650}>Your credentials stay with your organization</AppText>
                <AppText size="xs" c="dimmed" mt={2}>Firewall Manager never sees or stores your provider password.</AppText>
              </div>
            </div>
            <AppGroup className="fm-login-footer" justify="space-between" mt="xl">
              <AppText size="xs" c="dimmed">OIDC · Authorization Code flow</AppText>
              <AppText size="xs" c="dimmed">Need access? Contact an administrator.</AppText>
            </AppGroup>
          </div>
        </section>
        <aside className="fm-login-visual" aria-label="Protected network visualization">
          <div className="fm-login-visual-caption">
            <AppText size="xs" fw={750} tt="uppercase" lts=".12em">Protected network</AppText>
            <AppText size="sm" c="dimmed" mt={4}>One control plane. Every policy path.</AppText>
          </div>
        </aside>
      </div>
    </main>
  );
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
      leftSection={<span className="fm-provider-initial">{provider.display_name.slice(0, 1).toUpperCase()}</span>}
    >
      <span className="fm-provider-label"><span>{provider.display_name}</span><small>{provider.kind.toUpperCase()} identity provider</small></span>
    </AppButton>
  );
}
