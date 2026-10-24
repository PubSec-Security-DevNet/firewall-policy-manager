// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';

import {
  ApiError,
  authenticationRequiredEvent,
  loadInitialOverview,
  type Overview,
  type Session,
} from '../../api/client';

type OverviewState =
  | { status: 'loading' }
  | { status: 'ready'; overview: Overview; session: Session }
  | { status: 'unauthenticated'; sessionExpired: boolean }
  | { status: 'error'; message: string; correlationId?: string };

export function useOverview(): OverviewState {
  const [state, setState] = useState<OverviewState>({ status: 'loading' });

  useEffect(() => {
    let active = true;
    const requireAuthentication = () => {
      if (!active) return;
      // Discard the authenticated tree and ignore late results from this session.
      active = false;
      setState((current) => ({
        status: 'unauthenticated',
        sessionExpired: current.status === 'ready',
      }));
    };
    window.addEventListener(authenticationRequiredEvent, requireAuthentication);
    void loadInitialOverview()
      .then(({ overview, session }) => {
        if (active) setState({ status: 'ready', overview, session });
      })
      .catch((error: unknown) => {
        if (!active) return;
        if (error instanceof ApiError) {
          if (error.code === 'NOT_AUTHENTICATED') {
            requireAuthentication();
            return;
          }
          setState({
            status: 'error',
            message: error.message,
            correlationId: error.correlationId,
          });
          return;
        }
        setState({ status: 'error', message: 'The application API is unavailable.' });
      });
    return () => {
      active = false;
      window.removeEventListener(authenticationRequiredEvent, requireAuthentication);
    };
  }, []);

  return state;
}
