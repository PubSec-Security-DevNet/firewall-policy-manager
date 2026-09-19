import { useEffect, useState } from 'react';

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

export function useDelegatedWorkspace(groups: ActiveGroup[]) {
  const initialGroupId = groups.length === 1 ? (groups[0]?.id ?? '') : '';
  const [activeGroupId, setActiveGroupId] = useState(initialGroupId);
  const [activePolicyId, setActivePolicyId] = useState('');
  const [state, setState] = useState<WorkspaceState>(
    initialGroupId
      ? { status: 'loading', activeGroupId: initialGroupId, policies: [] }
      : groups.length === 0
        ? { status: 'unavailable', reason: 'You do not have an enabled Group membership.' }
        : { status: 'unavailable', reason: 'Select the Group you want to work as.' },
  );

  useEffect(() => {
    if (!activeGroupId) return;
    let current = true;
    void loadDelegatedPolicies(activeGroupId)
      .then((policies) => {
        if (!current) return;
        if (policies.length === 0) {
          setState({
            status: 'unavailable',
            reason: 'No Access Policy is delegated to this Group.',
          });
          return;
        }
        const policyId = policies[0]?.id;
        if (!policyId) return;
        setActivePolicyId(policyId);
        return loadDelegatedContext(activeGroupId, policyId).then((context) => {
          if (current) {
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
        if (!current) return;
        setState(errorState(activeGroupId, error));
      });
    return () => {
      current = false;
    };
  }, [activeGroupId]);

  const selectGroup = (groupId: string) => {
    // Clear every resource from the previous Group before loading the next context.
    setActiveGroupId(groupId);
    setActivePolicyId('');
    setState(
      groupId
        ? { status: 'loading', activeGroupId: groupId, policies: [] }
        : { status: 'unavailable', reason: 'Select the Group you want to work as.' },
    );
  };
  const selectPolicy = (policyId: string) => {
    setActivePolicyId(policyId);
    if (state.status === 'ready' && policyId) {
      const policies = state.policies;
      setState({
        status: 'loading',
        activeGroupId,
        activePolicyId: policyId,
        policies,
      });
      void loadDelegatedContext(activeGroupId, policyId)
        .then((context) => {
          setState({
            status: 'ready',
            activeGroupId,
            activePolicyId: policyId,
            policies,
            context,
          });
        })
        .catch((error: unknown) => setState(errorState(activeGroupId, error)));
    }
  };
  return {
    state,
    activeGroupId,
    activePolicyId,
    setActiveGroupId: selectGroup,
    setActivePolicyId: selectPolicy,
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
