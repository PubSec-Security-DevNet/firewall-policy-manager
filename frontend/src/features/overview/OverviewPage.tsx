import {
  AppErrorState,
  AppIdentityNotice,
  AppLoadingState,
  AppMetricGrid,
  AppPage,
  AppProviderGrid,
} from '../../ui';
import { DelegatedWorkspace } from '../delegated/DelegatedWorkspace';
import { AdministrationPanel } from '../admin/AdministrationPanel';
import { ProviderConnectionsPanel } from '../provider-connections/ProviderConnectionsPanel';
import { Tabs } from '../../ui/tabs';
import { useOverview } from './useOverview';

export function OverviewPage() {
  const state = useOverview();

  if (state.status === 'loading') {
    return (
      <AppPage title="Control plane overview" description="Loading local development data.">
        <AppLoadingState label="Loading inventory" />
      </AppPage>
    );
  }
  if (state.status === 'error') {
    return (
      <AppPage title="Control plane overview" description="The application could not load.">
        <AppErrorState message={state.message} reference={state.correlationId} />
      </AppPage>
    );
  }
  return (
    <AppPage
      title={state.overview.organization}
      description="Normalized, read-only inventory synchronized from the FMC and SCC mocks."
    >
      <AppIdentityNotice email={state.session.email} role={state.session.role} />
      <AppMetricGrid values={state.overview.counts} />
      <AppProviderGrid providers={state.overview.providers} />
      {state.session.role === 'admin' ? (
        <Tabs defaultValue="provider-connections">
          <Tabs.List aria-label="Administration area">
            <Tabs.Tab value="provider-connections">Provider connections</Tabs.Tab>
            <Tabs.Tab value="authorization">Authorization</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="provider-connections" pt="md">
            <ProviderConnectionsPanel />
          </Tabs.Panel>
          <Tabs.Panel value="authorization" pt="md">
            <AdministrationPanel />
          </Tabs.Panel>
        </Tabs>
      ) : (
        <DelegatedWorkspace groups={state.session.groups} />
      )}
    </AppPage>
  );
}
