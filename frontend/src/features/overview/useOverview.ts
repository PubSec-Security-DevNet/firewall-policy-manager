import { useEffect, useState } from 'react';

import { ApiError, loadInitialOverview, type Overview, type Session } from '../../api/client';

type OverviewState =
  | { status: 'loading' }
  | { status: 'ready'; overview: Overview; session: Session }
  | { status: 'unauthenticated' }
  | { status: 'error'; message: string; correlationId?: string };

export function useOverview(): OverviewState {
  const [state, setState] = useState<OverviewState>({ status: 'loading' });

  useEffect(() => {
    let active = true;
    void loadInitialOverview()
      .then(({ overview, session }) => {
        if (active) setState({ status: 'ready', overview, session });
      })
      .catch((error: unknown) => {
        if (!active) return;
        if (error instanceof ApiError) {
          if (error.code === 'NOT_AUTHENTICATED') {
            setState({ status: 'unauthenticated' });
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
    };
  }, []);

  return state;
}
