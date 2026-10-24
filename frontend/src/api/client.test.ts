// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { authenticationRequiredEvent, loadSmtpSettings, updateSmtpSettings } from './client';

describe('API authentication failures', () => {
  const onAuthenticationRequired = vi.fn();

  beforeEach(() => {
    window.sessionStorage.clear();
    onAuthenticationRequired.mockClear();
    window.addEventListener(authenticationRequiredEvent, onAuthenticationRequired);
  });

  afterEach(() => {
    window.removeEventListener(authenticationRequiredEvent, onAuthenticationRequired);
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    window.sessionStorage.clear();
  });

  it.each([
    ['plain text', () => new Response('Unauthorized', { status: 401 })],
    ['empty body', () => new Response(null, { status: 401 })],
    ['unexpected JSON', () => Response.json({ detail: 'Unauthorized' }, { status: 401 })],
    [
      'authentication error code',
      () =>
        Response.json(
          {
            error: {
              code: 'NOT_AUTHENTICATED',
              message: 'Session expired.',
              correlation_id: 'ref',
            },
          },
          { status: 403 },
        ),
    ],
  ])('requires sign-in for %s and discards only cached working context', async (_, response) => {
    window.sessionStorage.setItem('firewall-manager.active-context.user', 'private context');
    window.sessionStorage.setItem('unrelated-preference', 'keep');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response()));

    await expect(loadSmtpSettings()).rejects.toMatchObject({ code: 'NOT_AUTHENTICATED' });
    expect(onAuthenticationRequired).toHaveBeenCalledOnce();
    expect(window.sessionStorage.getItem('firewall-manager.active-context.user')).toBeNull();
    expect(window.sessionStorage.getItem('unrelated-preference')).toBe('keep');
  });

  it('does not replay a mutation rejected after expiry', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 401 }));
    vi.stubGlobal('fetch', fetch);

    await expect(updateSmtpSettings({ host: 'smtp.example.test' })).rejects.toMatchObject({
      code: 'NOT_AUTHENTICATED',
    });
    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/admin/smtp',
      expect.objectContaining({ method: 'PUT' }),
    );
  });

  it.each([
    [403, 'ACTION_NOT_GRANTED'],
    [409, 'STALE_REVISION'],
    [500, 'INTERNAL_ERROR'],
    [502, 'PROVIDER_AUTHENTICATION_FAILED'],
  ])('preserves %s %s as a feature error', async (status, code) => {
    const details = { reason: 'Example failure' };
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          Response.json(
            { error: { code, message: 'Request failed.', correlation_id: 'ref', details } },
            { status },
          ),
        ),
    );
    await expect(loadSmtpSettings()).rejects.toMatchObject({ code, correlationId: 'ref', details });
    expect(onAuthenticationRequired).not.toHaveBeenCalled();
  });

  it('still requires sign-in when browser context storage cannot be cleared', async () => {
    window.sessionStorage.setItem('firewall-manager.active-context.user', 'private context');
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
      throw new DOMException('Storage unavailable', 'SecurityError');
    });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 401 })));
    await expect(loadSmtpSettings()).rejects.toMatchObject({ code: 'NOT_AUTHENTICATED' });
    expect(onAuthenticationRequired).toHaveBeenCalledOnce();
  });
});
