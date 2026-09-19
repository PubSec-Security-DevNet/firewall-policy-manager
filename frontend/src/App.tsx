import { OverviewPage } from './features/overview/OverviewPage';
import { DevelopmentUserSelector } from './features/auth/DevelopmentUserSelector';
import { AppLayout } from './ui';

export function App() {
  return (
    <AppLayout headerActions={<DevelopmentUserSelector />}>
      <OverviewPage />
    </AppLayout>
  );
}
