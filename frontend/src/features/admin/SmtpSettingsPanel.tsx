import { useEffect, useState } from 'react';

import { loadSmtpSettings, updateSmtpSettings, type SmtpSettings } from '../../api/client';
import {
  AppAlert,
  AppButton,
  AppCard,
  AppCheckbox,
  AppLoadingState,
  AppSection,
  AppSelect,
  AppStack,
  AppText,
  AppTextarea,
  AppTextInput,
} from '../../ui';

type Draft = {
  host: string;
  port: string;
  from_address: string;
  encryption: SmtpSettings['encryption'];
  authentication_required: boolean;
  username: string;
  password: string;
  password_configured: boolean;
  custom_ca_configured: boolean;
  custom_ca_certificate: string;
  clear_custom_ca: boolean;
  revision: number;
};

export function SmtpSettingsPanel() {
  const [draft, setDraft] = useState<Draft>();
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const refresh = () =>
    loadSmtpSettings()
      .then((settings) => {
        setDraft({
          host: settings.host,
          port: String(settings.port),
          from_address: settings.from_address,
          encryption: settings.encryption,
          authentication_required: settings.authentication_required,
          username: settings.username ?? '',
          password: '',
          password_configured: settings.password_configured,
          custom_ca_configured: settings.custom_ca_configured,
          custom_ca_certificate: '',
          clear_custom_ca: false,
          revision: settings.revision,
        });
      })
      .catch((reason: unknown) =>
        setError(reason instanceof Error ? reason.message : 'Unable to load SMTP settings.'),
      )
      .finally(() => setLoading(false));

  useEffect(() => {
    void refresh();
  }, []);

  if (loading || !draft) return <AppLoadingState label="Loading SMTP settings" />;
  const update = <K extends keyof Draft>(key: K, value: Draft[K]) =>
    setDraft((current) => (current ? { ...current, [key]: value } : current));
  const save = () => {
    setError('');
    setMessage('');
    const payload: Record<string, unknown> = {
      host: draft.host,
      port: Number(draft.port),
      from_address: draft.from_address,
      encryption: draft.encryption,
      authentication_required: draft.authentication_required,
      username: draft.authentication_required ? draft.username : null,
      expected_revision: draft.revision,
    };
    if (draft.password) payload.password = draft.password;
    if (draft.clear_custom_ca) payload.custom_ca_certificate = '';
    else if (draft.custom_ca_certificate.trim())
      payload.custom_ca_certificate = draft.custom_ca_certificate;
    void updateSmtpSettings(payload)
      .then((settings) => {
        setMessage('SMTP settings saved. Approval notifications will use this profile.');
        setDraft((current) =>
          current
            ? {
                ...current,
                password: '',
                password_configured: settings.password_configured,
                custom_ca_certificate: '',
                custom_ca_configured: settings.custom_ca_configured,
                clear_custom_ca: false,
                revision: settings.revision,
              }
            : current,
        );
      })
      .catch((reason: unknown) =>
        setError(reason instanceof Error ? reason.message : 'Unable to save SMTP settings.'),
      );
  };
  return (
    <AppStack gap="lg">
      {message && <AppAlert color="green">{message}</AppAlert>}
      {error && <AppAlert color="red">{error}</AppAlert>}
      <AppCard>
        <AppSection
          title="SMTP delivery"
          description="Configure the server used for approval and operational email notifications. Credentials are encrypted server-side and never returned to the browser."
        >
          <AppStack gap="sm">
            <AppTextInput
              label="SMTP host"
              placeholder="smtp.example.com"
              value={draft.host}
              onChange={(event) => update('host', event.currentTarget.value)}
            />
            <AppTextInput
              label="Port"
              type="number"
              value={draft.port}
              onChange={(event) => update('port', event.currentTarget.value)}
            />
            <AppTextInput
              label="From address"
              type="email"
              placeholder="firewall-manager@example.com"
              value={draft.from_address}
              onChange={(event) => update('from_address', event.currentTarget.value)}
            />
            <AppSelect
              label="Encryption"
              description="STARTTLS upgrades a plain SMTP connection; SSL/TLS starts encrypted."
              data={[
                { value: 'NONE', label: 'None' },
                { value: 'STARTTLS', label: 'STARTTLS' },
                { value: 'SSL_TLS', label: 'SSL/TLS' },
              ]}
              value={draft.encryption}
              onChange={(value) =>
                update('encryption', (value ?? 'STARTTLS') as Draft['encryption'])
              }
            />
            <AppCheckbox
              label="SMTP server requires authentication"
              checked={draft.authentication_required}
              onChange={(event) => update('authentication_required', event.currentTarget.checked)}
            />
            {draft.authentication_required && (
              <>
                <AppTextInput
                  label="Username"
                  value={draft.username}
                  onChange={(event) => update('username', event.currentTarget.value)}
                />
                <AppTextInput
                  label="Password"
                  description={
                    draft.password_configured
                      ? 'Leave blank to keep the existing password.'
                      : undefined
                  }
                  type="password"
                  value={draft.password}
                  onChange={(event) => update('password', event.currentTarget.value)}
                />
              </>
            )}
            <AppTextarea
              label="Custom CA certificate (PEM)"
              description={
                draft.custom_ca_configured
                  ? 'A custom CA is saved. Paste a replacement or leave blank to keep it.'
                  : 'Optional. Used to verify STARTTLS or SSL/TLS certificates signed by a private CA.'
              }
              minRows={6}
              value={draft.custom_ca_certificate}
              onChange={(event) => update('custom_ca_certificate', event.currentTarget.value)}
            />
            {draft.custom_ca_configured && (
              <AppCheckbox
                label="Remove saved custom CA certificate"
                checked={draft.clear_custom_ca}
                onChange={(event) => update('clear_custom_ca', event.currentTarget.checked)}
              />
            )}
            <AppButton onClick={save}>Save SMTP settings</AppButton>
            {!draft.host && (
              <AppText size="sm" c="dimmed">
                SMTP is not configured yet. Notifications remain queued until these settings are
                saved.
              </AppText>
            )}
          </AppStack>
        </AppSection>
      </AppCard>
    </AppStack>
  );
}
