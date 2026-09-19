import { MantineProvider } from '@mantine/core';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { appTheme } from '../../ui/theme';
import { DevelopmentUserSelector } from './DevelopmentUserSelector';

afterEach(() => vi.restoreAllMocks());

describe('DevelopmentUserSelector', () => {
  it('loads representative runtime identities from the development-only endpoint', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          Response.json([
            {
              email: 'admin@example.test',
              display_name: 'Platform Admin',
              role: 'admin',
              enabled: true,
            },
            {
              email: 'disabled@example.test',
              display_name: 'Disabled User',
              role: 'viewer',
              enabled: false,
            },
          ]),
        ),
      ),
    );
    render(
      <MantineProvider theme={appTheme}>
        <DevelopmentUserSelector />
      </MantineProvider>,
    );

    const selector = await screen.findByRole('textbox', { name: 'Development user' });
    await userEvent.setup().click(selector);
    expect(screen.getByText(/Platform Admin — admin/)).toBeInTheDocument();
    expect(screen.getByText(/Disabled User — viewer \(disabled\)/)).toBeInTheDocument();
  });
});
