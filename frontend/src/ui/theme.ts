// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { createTheme, rem } from '@mantine/core';

export const appTheme = createTheme({
  primaryColor: 'sky',
  primaryShade: { light: 6, dark: 5 },
  colors: {
    sky: [
      '#e8f8ff',
      '#d0eeff',
      '#9edcff',
      '#68c9ff',
      '#3ab7fd',
      '#1aa8f4',
      '#0799e5',
      '#0084cc',
      '#0076b9',
      '#0065a1',
    ],
  },
  defaultRadius: 'sm',
  fontFamily: 'Inter, "Segoe UI", ui-sans-serif, system-ui, sans-serif',
  fontFamilyMonospace: '"SFMono-Regular", Consolas, monospace',
  headings: {
    fontFamily: 'Inter, "Segoe UI", ui-sans-serif, system-ui, sans-serif',
    fontWeight: '650',
  },
  spacing: { xs: rem(8), sm: rem(12), md: rem(16), lg: rem(24), xl: rem(32) },
  radius: { xs: rem(3), sm: rem(6), md: rem(9), lg: rem(12), xl: rem(16) },
  shadows: {
    xs: '0 1px 2px rgb(0 0 0 / 22%)',
    sm: '0 8px 24px rgb(0 0 0 / 18%)',
    md: '0 16px 48px rgb(0 0 0 / 28%)',
  },
  cursorType: 'pointer',
  defaultGradient: { from: 'sky.7', to: 'cyan.6', deg: 120 },
  components: {
    Button: { defaultProps: { size: 'sm' } },
    TextInput: { defaultProps: { size: 'sm' } },
    Select: { defaultProps: { size: 'sm' } },
    Textarea: { defaultProps: { size: 'sm' } },
  },
});
