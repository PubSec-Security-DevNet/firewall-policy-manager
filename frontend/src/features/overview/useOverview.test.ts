// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';

import { loadSmtpSettings } from '../../api/client';
import { useOverview } from './useOverview';

afterEach(() => vi.unstubAllGlobals());

it('ignores late initial data after another request requires authentication', async () => {
  let completeOverview!: (response: Response) => void;
  const pendingOverview = new Promise<Response>((resolve) => {
    completeOverview = resolve;
  });
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string) => {
      if (path === '/api/v1/overview') return pendingOverview;
      if (path === '/api/v1/session') return Promise.resolve(Response.json({ groups: [] }));
      return Promise.resolve(new Response(null, { status: 401 }));
    }),
  );

  const { result } = renderHook(useOverview);
  expect(result.current.status).toBe('loading');
  await act(async () => {
    await expect(loadSmtpSettings()).rejects.toMatchObject({ code: 'NOT_AUTHENTICATED' });
  });
  await waitFor(() => expect(result.current.status).toBe('unauthenticated'));
  await act(async () => {
    completeOverview(Response.json({ providers: [], counts: {} }));
    await pendingOverview;
  });
  expect(result.current.status).toBe('unauthenticated');
});
