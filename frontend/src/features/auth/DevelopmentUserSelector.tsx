import { useEffect, useState } from 'react';

import {
  getDevelopmentUser,
  loadDevelopmentIdentities,
  switchDevelopmentUser,
  developmentIdentitiesChangedEvent,
  type DevelopmentIdentity,
} from '../../api/client';
import { AppSelect as Select } from '../../ui';

export function DevelopmentUserSelector({ compact = false }: { compact?: boolean }) {
  const [identities, setIdentities] = useState<DevelopmentIdentity[]>([]);

  useEffect(() => {
    let active = true;
    const refresh = () =>
      loadDevelopmentIdentities()
        .then((values) => {
          if (active) setIdentities(values);
        })
        .catch(() => {
          // The endpoint is intentionally absent outside explicit development auth mode.
        });
    void refresh();
    const onIdentitiesChanged = () => {
      void refresh();
    };
    window.addEventListener(developmentIdentitiesChangedEvent, onIdentitiesChanged);
    return () => {
      active = false;
      window.removeEventListener(developmentIdentitiesChangedEvent, onIdentitiesChanged);
    };
  }, []);

  if (identities.length === 0) return null;
  return (
    <div className={compact ? 'fm-dev-user-selector' : undefined}>
      <Select
        aria-label="Development user"
        description={compact ? undefined : 'DEV USER'}
        leftSection={
          compact ? (
            <span style={{ fontSize: 9, fontWeight: 800, color: 'var(--fm-warning)' }}>DEV</span>
          ) : undefined
        }
        w={compact ? 250 : 260}
        value={getDevelopmentUser()}
        onChange={(email) => {
          if (email) switchDevelopmentUser(email);
        }}
        data={identities.map((identity) => ({
          value: identity.email,
          label: `${identity.display_name} — ${identity.role}${identity.enabled ? '' : ' (disabled)'}`,
        }))}
      />
    </div>
  );
}
