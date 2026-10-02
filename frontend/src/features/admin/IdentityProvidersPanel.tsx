import { useEffect, useState } from 'react';

import {
  createOidcProvider,
  loadOidcProviders,
  rotateOidcProviderSecret,
  updateOidcProvider,
  type OidcProvider,
} from '../../api/client';
import {
  AppAlert,
  AppButton,
  AppCard,
  AppEmptyState,
  AppLoadingState,
  AppSection,
  AppSelect,
  AppStack,
  AppText,
  AppTextInput,
} from '../../ui';

export function IdentityProvidersPanel() {
  const [providers, setProviders] = useState<OidcProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [draft, setDraft] = useState({ kind: 'generic', display_name: '', issuer_url: '', client_id: '', client_secret: '', mapping_claim: 'email' });
  const refresh = () => loadOidcProviders().then(setProviders).finally(() => setLoading(false));
  useEffect(() => { void refresh(); }, []);
  if (loading) return <AppLoadingState label="Loading identity providers" />;
  const update = (key: string, value: string) => setDraft((current) => ({ ...current, [key]: value }));
  return (
    <AppStack gap="lg">
      {message && <AppAlert color="green">{message}</AppAlert>}
      <AppCard>
        <AppSection title="Configured identity providers" description="Client secrets are write-only and encrypted server-side. They are never returned to this page.">
          {providers.length === 0 && <AppEmptyState title="No identity providers" description="Add Entra ID, Duo SSO, or a generic OIDC provider below." />}
          {providers.map((provider) => <ProviderRow key={provider.id} provider={provider} onSaved={() => { setMessage('Provider updated.'); void refresh(); }} />)}
        </AppSection>
      </AppCard>
      <AppCard>
        <AppSection title="Add identity provider" description="Register the issuer and client credentials. Users must already be provisioned with issuer and subject mappings.">
          <AppStack gap="sm">
            <AppSelect label="Provider type" data={[{ value: 'entra', label: 'Microsoft Entra ID' }, { value: 'duo', label: 'Cisco Duo SSO' }, { value: 'generic', label: 'Generic OIDC' }]} value={draft.kind} onChange={(value) => update('kind', value ?? 'generic')} />
            <AppTextInput label="Display name" value={draft.display_name} onChange={(event) => update('display_name', event.currentTarget.value)} />
            <AppTextInput label="Generated provider ID" description="Used in the callback URL and generated from the display name." value={providerSlug(draft.display_name)} readOnly />
            <ProviderSetupGuidance kind={draft.kind} providerId={providerSlug(draft.display_name)} />
            <AppTextInput label="Issuer URL" placeholder="https://issuer.example.com" value={draft.issuer_url} onChange={(event) => update('issuer_url', event.currentTarget.value)} />
            <AppTextInput label="Client ID" value={draft.client_id} onChange={(event) => update('client_id', event.currentTarget.value)} />
            <AppTextInput label="Client secret" type="password" value={draft.client_secret} onChange={(event) => update('client_secret', event.currentTarget.value)} />
            <AppTextInput label="User mapping claim" description="Claim matched exactly against an existing application User email." value={draft.mapping_claim} onChange={(event) => update('mapping_claim', event.currentTarget.value)} />
            <AppButton disabled={!providerSlug(draft.display_name)} onClick={() => { void createOidcProvider({ ...draft, id: providerSlug(draft.display_name) }).then(() => { setMessage('Provider created.'); setDraft({ kind: 'generic', display_name: '', issuer_url: '', client_id: '', client_secret: '', mapping_claim: 'email' }); return refresh(); }); }}>Save provider</AppButton>
          </AppStack>
        </AppSection>
      </AppCard>
    </AppStack>
  );
}

function ProviderSetupGuidance({ kind, providerId }: { kind: string; providerId: string }) {
  const callback = `${window.location.origin}/api/v1/auth/${providerId || '<generated-id>'}/callback`;
  const guidance = kind === 'entra'
    ? 'In Entra, create an OpenID Connect web application registration. Use your tenant issuer (https://login.microsoftonline.com/<tenant-id>/v2.0), the client ID and secret, and request openid profile email scopes. Do not request offline_access or enable refresh tokens.'
    : kind === 'duo'
      ? 'In Duo, choose Generic OIDC Relying Party with Authorization Code. Enable openid, email, and profile scopes. Do not enable offline_access or refresh tokens. Copy Issuer, Client ID, and Client Secret from Duo Metadata. Do not enter Duo Discovery, Token, JWKS, or UserInfo URLs here; Firewall Manager discovers them from the issuer.'
      : 'Use a standards-compliant OIDC provider. Enter its issuer URL, client ID, and secret. Request openid profile email scopes; do not request offline_access or refresh tokens. Firewall Manager uses the standard /.well-known/openid-configuration document to discover the remaining endpoints.';
  return <AppAlert color="blue"><AppText size="sm">{guidance}</AppText><AppText size="sm" mt="xs">Register this exact sign-in redirect URL with the provider: <code>{callback}</code></AppText></AppAlert>;
}

function providerSlug(displayName: string): string {
  return displayName
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

function ProviderRow({ provider, onSaved }: { provider: OidcProvider; onSaved: () => void }) {
  const [secret, setSecret] = useState('');
  const redirectUrl = `${window.location.origin}/api/v1/auth/${encodeURIComponent(provider.provider_id)}/callback`;
  return <AppCard withBorder><AppStack gap="xs"><AppText fw={700}>{provider.display_name} ({provider.kind})</AppText><AppText size="sm">Issuer: {provider.issuer_url}</AppText><AppText size="sm">Client ID: {provider.client_id} · Secret configured: yes</AppText><AppText size="sm">Sign-in redirect URL: <code>{redirectUrl}</code></AppText><AppTextInput label="Rotate client secret" type="password" value={secret} onChange={(event) => setSecret(event.currentTarget.value)} /><AppButton disabled={!secret} onClick={() => { void rotateOidcProviderSecret(provider, secret).then(() => { setSecret(''); onSaved(); }); }}>Rotate secret</AppButton><AppButton component="a" href={`/api/v1/auth/${encodeURIComponent(provider.provider_id)}/test`} target="_blank" rel="noreferrer">Test OIDC configuration</AppButton><AppButton variant="subtle" onClick={() => { void updateOidcProvider(provider, { enabled: !provider.enabled }).then(onSaved); }}>{provider.enabled ? 'Disable' : 'Enable'}</AppButton></AppStack></AppCard>;
}
