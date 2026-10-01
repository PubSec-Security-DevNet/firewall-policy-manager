import {
  Alert,
  AppShell,
  Badge,
  Burger,
  Button,
  Card,
  Checkbox,
  Container,
  Divider,
  Drawer,
  Group,
  Loader,
  Menu,
  Modal,
  MultiSelect,
  Paper,
  Progress,
  Radio,
  ScrollArea,
  SegmentedControl,
  Select,
  SimpleGrid,
  Skeleton,
  Stack,
  Table,
  Tabs,
  Text,
  TextInput,
  Textarea,
  ThemeIcon,
  Title,
  Tooltip,
} from '@mantine/core';
import type { ButtonProps, CardProps } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import {
  IconAlertTriangle,
  IconArrowsShuffle,
  IconBell,
  IconBuildingCommunity,
  IconChevronRight,
  IconCloudLock,
  IconFileDiff,
  IconHistory,
  IconHome,
  IconLockAccess,
  IconPackages,
  IconPlugConnected,
  IconRocket,
  IconSearch,
  IconServerCog,
  IconShieldCheck,
  IconShieldLock,
  IconUsersGroup,
  type Icon,
} from '@tabler/icons-react';
import type {
  ComponentPropsWithoutRef,
  ComponentType,
  ElementType,
  FormEventHandler,
  ReactNode,
} from 'react';

import type { Session } from '../api/client';

export type AppRoute =
  | 'home'
  | 'policies'
  | 'rules'
  | 'objects'
  | 'changes'
  | 'changesets-admin'
  | 'approvals'
  | 'deployments'
  | 'providers'
  | 'sync'
  | 'users'
  | 'groups'
  | 'grants'
  | 'audit';

interface NavigationItem {
  value: AppRoute;
  label: string;
  icon: Icon;
}
interface NavigationSection {
  label?: string;
  items: NavigationItem[];
}

const baseNavigation: NavigationSection[] = [
  { items: [{ value: 'home', label: 'Home', icon: IconHome }] },
  {
    label: 'Firewall management',
    items: [
      { value: 'policies', label: 'Policies', icon: IconShieldCheck },
      { value: 'rules', label: 'Rules', icon: IconLockAccess },
      { value: 'objects', label: 'Objects', icon: IconPackages },
      { value: 'changes', label: 'Changes', icon: IconFileDiff },
    ],
  },
];
const adminNavigation: NavigationSection[] = [
  {
    label: 'Access & delegation',
    items: [
      { value: 'users', label: 'Users', icon: IconUsersGroup },
      { value: 'groups', label: 'Groups', icon: IconBuildingCommunity },
      { value: 'grants', label: 'Access grants', icon: IconShieldLock },
    ],
  },
  {
    label: 'Infrastructure',
    items: [
      { value: 'providers', label: 'Provider connections', icon: IconPlugConnected },
      { value: 'sync', label: 'Sync & drift', icon: IconArrowsShuffle },
    ],
  },
  {
    label: 'Operations',
    items: [
      { value: 'changesets-admin', label: 'All ChangeSets', icon: IconFileDiff },
      { value: 'deployments', label: 'Deployments', icon: IconRocket },
      { value: 'audit', label: 'Audit', icon: IconHistory },
    ],
  },
];
const approvalNavigation: NavigationSection[] = [
  {
    label: 'Approvals',
    items: [{ value: 'approvals', label: 'Pending approvals', icon: IconBell }],
  },
];

export function AppLayout({
  children,
  headerActions,
  session,
  workingGroup,
  workingPolicy,
  route,
  onRouteChange,
  approvalCount = 0,
}: {
  children: ReactNode;
  headerActions?: ReactNode;
  session?: Session;
  workingGroup?: string;
  workingPolicy?: string;
  route?: AppRoute;
  onRouteChange?: (route: AppRoute) => void;
  approvalCount?: number;
}) {
  const [opened, { toggle, close }] = useDisclosure(false);
  const canApprove = ['approver', 'firewall_admin', 'admin'].includes(session?.role ?? '');
  const navigation =
    session?.role === 'admin'
      ? [...baseNavigation, ...adminNavigation, ...approvalNavigation]
      : canApprove
        ? [...baseNavigation, ...approvalNavigation]
        : baseNavigation;
  const navbar = (
    <Stack h="100%" gap={0}>
      <div className="fm-working-context">
        <Text className="fm-working-context-label">Working Group</Text>
        <Text className="fm-working-context-value">{workingGroup ?? 'Select a Group'}</Text>
        <Text className="fm-working-context-label" mt={7}>
          Access Policy
        </Text>
        <Text className="fm-working-context-policy">
          {workingPolicy ?? 'Select an Access Policy'}
        </Text>
      </div>
      <ScrollArea flex={1} type="auto" offsetScrollbars>
        <div>
          {navigation.map((section, index) => (
            <div className="fm-nav-section" key={section.label ?? index}>
              {section.label && <div className="fm-nav-label">{section.label}</div>}
              {section.items.map((item) => {
                const NavIcon = item.icon;
                return (
                  <button
                    className="fm-nav-item"
                    data-active={route === item.value}
                    aria-current={route === item.value ? 'page' : undefined}
                    key={item.value}
                    onClick={() => {
                      onRouteChange?.(item.value);
                      close();
                    }}
                  >
                    <NavIcon size={18} stroke={1.7} aria-hidden="true" />
                    <span>{item.label}</span>
                    {route === item.value && (
                      <IconChevronRight
                        size={14}
                        style={{ marginLeft: 'auto' }}
                        aria-hidden="true"
                      />
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </ScrollArea>
      <div className="fm-nav-footer">
        <Group gap="xs" wrap="nowrap">
          <ThemeIcon color="teal" variant="light" size="sm">
            <IconServerCog size={14} />
          </ThemeIcon>
          <div>
            <Text size="xs" fw={650}>
              Control plane healthy
            </Text>
            <Text size="10px" c="dimmed">
              API available
            </Text>
          </div>
        </Group>
      </div>
    </Stack>
  );
  return (
    <AppShell
      className="fm-shell"
      header={{ height: 64 }}
      navbar={{ width: 248, breakpoint: 'md', collapsed: { mobile: !opened } }}
      padding={0}
    >
      <a className="fm-skip" href="#main-content">
        Skip to main content
      </a>
      <AppShell.Header className="fm-topbar">
        <Group h="100%" px={{ base: 'md', md: 'lg' }} justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger
              className="fm-mobile-only"
              opened={opened}
              onClick={toggle}
              size="sm"
              aria-label="Toggle navigation"
            />
            <Group className="fm-topbar-brand" gap="sm" wrap="nowrap">
              <div className="fm-brand-mark" aria-hidden="true">
                <IconShieldLock size={21} stroke={2.2} />
              </div>
              <div>
                <Text fw={700} size="sm" lh={1.15}>
                  Firewall Manager
                </Text>
                <Text size="10px" c="dimmed" tt="uppercase" fw={700} lts=".08em">
                  Security control plane
                </Text>
              </div>
            </Group>
          </Group>
          <Group gap="sm" wrap="nowrap">
            <Tooltip label="Global search is not yet available">
              <Button variant="subtle" color="gray" px={8} aria-label="Search">
                <IconSearch size={18} />
              </Button>
            </Tooltip>
            <Tooltip
              label={
                approvalCount ? `${approvalCount} approval(s) pending` : 'No pending approvals'
              }
            >
              <Button
                variant="subtle"
                color="gray"
                px={8}
                aria-label={approvalCount ? `${approvalCount} pending approvals` : 'Notifications'}
                onClick={() => onRouteChange?.('approvals')}
              >
                <IconBell size={18} />
                {approvalCount > 0 && (
                  <Badge size="xs" color="red" circle>
                    {approvalCount > 99 ? '99+' : approvalCount}
                  </Badge>
                )}
              </Button>
            </Tooltip>
            {session && (
              <div>
                <Text size="xs" fw={650} ta="right">
                  {session.email}
                </Text>
                <Text size="10px" c="dimmed" ta="right" tt="uppercase">
                  {session.role}
                </Text>
              </div>
            )}
            {headerActions}
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar className="fm-navbar" aria-label="Primary navigation">
        {navbar}
      </AppShell.Navbar>
      <AppShell.Main>
        <div id="main-content" className="fm-content">
          {children}
        </div>
      </AppShell.Main>
    </AppShell>
  );
}

export function AppPage({
  title,
  description,
  eyebrow,
  actions,
  children,
}: {
  title: string;
  description?: string;
  eyebrow?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Stack gap="lg">
      <header className="fm-page-header">
        <div>
          {eyebrow && (
            <Text className="fm-eyebrow" mb={4}>
              {eyebrow}
            </Text>
          )}
          <Title order={1} size="h2">
            {title}
          </Title>
          {description && (
            <Text c="dimmed" size="sm" maw={760} mt={4}>
              {description}
            </Text>
          )}
        </div>
        {actions && <Group>{actions}</Group>}
      </header>
      {children}
    </Stack>
  );
}

export function AppSection({
  title,
  description,
  actions,
  children,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section aria-labelledby={`section-${slug(title)}`}>
      <Group className="fm-section-header" justify="space-between" align="start">
        <div>
          <Title id={`section-${slug(title)}`} order={2} size="h4">
            {title}
          </Title>
          {description && (
            <Text c="dimmed" size="xs" mt={2}>
              {description}
            </Text>
          )}
        </div>
        {actions}
      </Group>
      {children}
    </section>
  );
}

export function AppLoadingState({ label }: { label: string }) {
  return (
    <Card className="fm-card" p="xl">
      <Stack role="status" aria-live="polite" align="center" gap="sm">
        <Loader size="sm" />
        <Text size="sm">{label}</Text>
        <Skeleton w="70%" h={8} />
      </Stack>
    </Card>
  );
}
export function AppErrorState({
  message,
  reference,
  title = 'Unable to load this view',
}: {
  message: string;
  reference?: string;
  title?: string;
}) {
  return (
    <Alert
      color="red"
      variant="light"
      title={title}
      icon={<IconAlertTriangle size={18} />}
      role="alert"
    >
      {message}
      {reference ? (
        <Text size="xs" mt={6}>
          Reference: <span className="fm-code">{reference}</span>
        </Text>
      ) : null}
    </Alert>
  );
}
export function AppEmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <Paper className="fm-subtle-panel" p="xl" ta="center">
      <IconCloudLock size={30} color="var(--fm-text-muted)" aria-hidden="true" />
      <Text fw={650} mt="sm">
        {title}
      </Text>
      <Text size="sm" c="dimmed" maw={520} mx="auto" mt={4}>
        {description}
      </Text>
      {action && (
        <Group justify="center" mt="md">
          {action}
        </Group>
      )}
    </Paper>
  );
}
export function AppIdentityNotice({ email, role }: { email: string; role: string }) {
  return (
    <Alert
      color="yellow"
      variant="light"
      title="Development identity"
      icon={<IconAlertTriangle size={18} />}
    >
      Requests use the real authorization path as <b>{email}</b> ({role}). Runtime switching is
      browser-session scoped and unavailable in production.
    </Alert>
  );
}

const statusColors: Record<string, string> = {
  HEALTHY: 'teal',
  CONNECTED: 'teal',
  COMPLETED: 'teal',
  SUCCESS: 'teal',
  READY: 'teal',
  SCHEDULED: 'yellow',
  OBSERVED: 'blue',
  ACTIVE: 'blue',
  OWNED: 'blue',
  ASSIGNED: 'teal',
  AVAILABLE: 'yellow',
  COUNT: 'cyan',
  WARNING: 'yellow',
  ATTENTION: 'yellow',
  PENDING: 'yellow',
  DRAFT: 'gray',
  READ_ONLY: 'gray',
  PROVIDER: 'gray',
  SHARED: 'violet',
  FAILED: 'red',
  ERROR: 'red',
  DRIFTED: 'orange',
  DISABLED: 'gray',
  RETIRED: 'gray',
  UNSUPPORTED: 'gray',
};
export function AppStatusBadge({
  value,
  label,
  size = 'sm',
}: {
  value: string | null | undefined;
  label?: string;
  size?: 'xs' | 'sm' | 'md' | 'lg';
}) {
  const key = (value ?? 'UNKNOWN').toUpperCase();
  return (
    <Badge size={size} color={statusColors[key] ?? 'gray'} variant="light" tt="none">
      {label ?? key.replaceAll('_', ' ')}
    </Badge>
  );
}
export function AppActionButton({
  intent = 'secondary',
  className,
  ...props
}: Omit<ButtonProps, 'color' | 'size' | 'variant'> &
  Omit<ComponentPropsWithoutRef<'button'>, 'color' | 'size'> & {
    intent?: 'secondary' | 'quiet' | 'success' | 'danger' | 'quiet-success' | 'quiet-danger';
  }) {
  return (
    <Button
      {...props}
      className={`fm-action-button fm-action-${intent}${className ? ` ${className}` : ''}`}
      color="gray"
      size="xs"
      variant="light"
    />
  );
}
export function AppProviderBadge({ provider }: { provider: string }) {
  return (
    <Badge color={provider.toLowerCase() === 'fmc' ? 'indigo' : 'cyan'} variant="outline">
      {provider.toUpperCase()}
    </Badge>
  );
}
export function AppDataTable({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <div className="fm-table-wrap" role="region" aria-label={label} tabIndex={0}>
      <Table className="fm-table" verticalSpacing="sm" horizontalSpacing="md" highlightOnHover>
        {children}
      </Table>
    </div>
  );
}
type SemanticCardProps = CardProps & {
  component?: ElementType;
  id?: string;
  onSubmit?: FormEventHandler<HTMLFormElement>;
  'aria-labelledby'?: string;
};
const SemanticCard = Card as unknown as ComponentType<SemanticCardProps>;
export function AppCard({
  children,
  interactive = false,
  className,
  ...props
}: {
  children: ReactNode;
  interactive?: boolean;
  component?: ElementType;
  id?: string;
  onSubmit?: FormEventHandler<HTMLFormElement>;
  'aria-labelledby'?: string;
} & Omit<CardProps, 'children'>) {
  return (
    <SemanticCard
      className={`fm-card${className ? ` ${className}` : ''}`}
      data-interactive={interactive}
      withBorder={false}
      p="lg"
      {...props}
    >
      {children}
    </SemanticCard>
  );
}
export function MetricCard({
  label,
  value,
  detail,
  icon,
}: {
  label: string;
  value: string | number;
  detail?: string;
  icon?: ReactNode;
}) {
  return (
    <AppCard className="fm-card fm-metric">
      <Group justify="space-between" align="start">
        <div>
          <Text size="xs" c="dimmed" tt="uppercase" fw={700} lts=".05em">
            {label}
          </Text>
          <Text size="30px" fw={700} lh={1.2} mt={7}>
            {value}
          </Text>
          {detail && (
            <Text size="xs" c="dimmed" mt={6}>
              {detail}
            </Text>
          )}
        </div>
        {icon && (
          <ThemeIcon variant="light" color="blue" size="lg">
            {icon}
          </ThemeIcon>
        )}
      </Group>
    </AppCard>
  );
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-');
}

export {
  Alert as AppAlert,
  Badge as AppBadge,
  Button as AppButton,
  Checkbox as AppCheckbox,
  Container as AppContainer,
  Divider as AppDivider,
  Drawer as AppDrawer,
  Group as AppGroup,
  Menu as AppMenu,
  Modal as AppDialog,
  MultiSelect as AppMultiSelect,
  Paper as AppPaper,
  Progress as AppProgress,
  Radio as AppRadio,
  SegmentedControl as AppSegmentedControl,
  Select as AppSelect,
  SimpleGrid as AppSimpleGrid,
  Stack as AppStack,
  Table as AppTable,
  Tabs as AppTabs,
  Text as AppText,
  TextInput as AppTextInput,
  Textarea as AppTextarea,
  ThemeIcon as AppThemeIcon,
  Title as AppTitle,
  Tooltip as AppTooltip,
};
