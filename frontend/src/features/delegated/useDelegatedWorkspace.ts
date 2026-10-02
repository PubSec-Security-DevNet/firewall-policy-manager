import { useEffect, useRef, useState } from 'react';

import {
  ApiError,
  loadDelegatedContext,
  loadDelegatedPolicies,
  type ActiveGroup,
  type DelegatedContext,
  type DelegatedPolicy,
} from '../../api/client';

type WorkspaceState =
  | { status: 'unavailable'; reason: string }
  | {
      status: 'loading';
      activeGroupId: string;
      policies: DelegatedPolicy[];
      activePolicyId?: string;
    }
  | {
      status: 'ready';
      activeGroupId: string;
      policies: DelegatedPolicy[];
      activePolicyId: string;
      context: DelegatedContext;
    }
  | { status: 'error'; activeGroupId: string; message: string; correlationId?: string };

export function useDelegatedWorkspace(
  groups: ActiveGroup[],
  preferredGroupId?: string,
  preferredPolicyId?: string,
  includeApplications = true,
  includeRules = true,
) {
  const initialGroupId = groups.some((group) => group.id === preferredGroupId)
    ? (preferredGroupId ?? '')
    : (groups[0]?.id ?? '');
  const [activeGroupId, setActiveGroupId] = useState(initialGroupId);
  const [activePolicyId, setActivePolicyId] = useState(preferredPolicyId ?? '');
  const requestedPolicyId = useRef(preferredPolicyId ?? '');
  const requestGeneration = useRef(0);
  const [state, setState] = useState<WorkspaceState>(
    initialGroupId
      ? { status: 'loading', activeGroupId: initialGroupId, policies: [] }
      : groups.length === 0
        ? { status: 'unavailable', reason: 'You do not have an enabled Group membership.' }
        : { status: 'unavailable', reason: 'Select the Group you want to work as.' },
  );

  useEffect(() => {
    if (!activeGroupId) return;
    const generation = ++requestGeneration.current;
    let current = true;
    void loadDelegatedPolicies(activeGroupId)
      .then((policies) => {
        if (!current || generation !== requestGeneration.current) return;
        if (policies.length === 0) {
          setState({
            status: 'unavailable',
            reason: 'No Access Policy is delegated to this Group.',
          });
          return;
        }
        const policyId = policies.some((policy) => policy.id === requestedPolicyId.current)
          ? requestedPolicyId.current
          : policies[0]?.id;
        if (!policyId) return;
        setActivePolicyId(policyId);
        setState({
          status: 'loading',
          activeGroupId,
          activePolicyId: policyId,
          policies,
        });
        return loadDelegatedContext(
          activeGroupId,
          policyId,
          includeApplications,
          includeRules,
        ).then((context) => {
          if (current && generation === requestGeneration.current) {
            setState({
              status: 'ready',
              activeGroupId,
              activePolicyId: policyId,
              policies,
              context,
            });
          }
        });
      })
      .catch((error: unknown) => {
        if (!current || generation !== requestGeneration.current) return;
        setState(errorState(activeGroupId, error));
      });
    return () => {
      current = false;
    };
  }, [activeGroupId, includeApplications, includeRules]);

  useEffect(() => {
    if (!activeGroupId || !activePolicyId || state.status !== 'ready') return;
    let current = true;
    let refreshing = false;
    const refresh = () => {
      if (refreshing) return;
      refreshing = true;
      void loadDelegatedContext(activeGroupId, activePolicyId, includeApplications, includeRules)
        .then((context) => {
          if (!current) return;
          setState((existing) =>
            existing.status === 'ready' &&
            existing.activeGroupId === activeGroupId &&
            existing.activePolicyId === activePolicyId
              ? { ...existing, context }
              : existing,
          );
        })
        .catch(() => {
          // Keep the last usable inventory during a transient refresh failure.
        })
        .finally(() => {
          refreshing = false;
        });
    };
    const timer = window.setInterval(refresh, 10_000);
    return () => {
      current = false;
      window.clearInterval(timer);
    };
  }, [activeGroupId, activePolicyId, includeApplications, includeRules, state.status]);

  const selectGroup = (groupId: string) => {
    // Clear every resource from the previous Group before loading the next context.
    requestGeneration.current += 1;
    setActiveGroupId(groupId);
    requestedPolicyId.current = '';
    setActivePolicyId('');
    setState(
      groupId
        ? { status: 'loading', activeGroupId: groupId, policies: [] }
        : { status: 'unavailable', reason: 'Select the Group you want to work as.' },
    );
  };
  const selectPolicy = (policyId: string) => {
    requestedPolicyId.current = policyId;
    setActivePolicyId(policyId);
    if (state.status === 'ready' && policyId) {
      const generation = ++requestGeneration.current;
      const policies = state.policies;
      setState({
        status: 'loading',
        activeGroupId,
        activePolicyId: policyId,
        policies,
      });
      void loadDelegatedContext(activeGroupId, policyId, includeApplications, includeRules)
        .then((context) => {
          if (generation !== requestGeneration.current) return;
          setState({
            status: 'ready',
            activeGroupId,
            activePolicyId: policyId,
            policies,
            context,
          });
        })
        .catch((error: unknown) => {
          if (generation === requestGeneration.current) setState(errorState(activeGroupId, error));
        });
    }
  };
  const activateMapping = (groupId: string, policyId: string) => {
    requestedPolicyId.current = policyId;
    requestGeneration.current += 1;
    setActivePolicyId(policyId);
    if (groupId !== activeGroupId) {
      setActiveGroupId(groupId);
      setState({
        status: 'loading',
        activeGroupId: groupId,
        activePolicyId: policyId,
        policies: [],
      });
      return;
    }
    selectPolicy(policyId);
  };
  return {
    state,
    activeGroupId,
    activePolicyId,
    setActiveGroupId: selectGroup,
    setActivePolicyId: selectPolicy,
    activateMapping,
  };
}

function errorState(activeGroupId: string, error: unknown): WorkspaceState {
  if (error instanceof ApiError) {
    return {
      status: 'error',
      activeGroupId,
      message: error.message,
      correlationId: error.correlationId,
    };
  }
  return { status: 'error', activeGroupId, message: 'The delegated workspace is unavailable.' };
}
