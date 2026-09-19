import { useEffect, useState } from 'react';

import {
  getDevelopmentUser,
  loadDevelopmentIdentities,
  switchDevelopmentUser,
  type DevelopmentIdentity,
} from '../../api/client';
import { AppSelect as Select } from '../../ui';

export function DevelopmentUserSelector() {
  const [identities, setIdentities] = useState<DevelopmentIdentity[]>([]);

  useEffect(() => {
    let active = true;
    void loadDevelopmentIdentities()
      .then((values) => {
        if (active) setIdentities(values);
      })
      .catch(() => {
        // The endpoint is intentionally absent outside explicit development auth mode.
      });
    return () => {
      active = false;
    };
  }, []);

  if (identities.length === 0) return null;
  return (
    <Select
      aria-label="Development user"
      w={260}
      value={getDevelopmentUser()}
      onChange={(email) => {
        if (email) switchDevelopmentUser(email);
      }}
      data={identities.map((identity) => ({
        value: identity.email,
        label: `${identity.display_name} — ${identity.role}${identity.enabled ? '' : ' (disabled)'}`,
      }))}
    />
  );
}
