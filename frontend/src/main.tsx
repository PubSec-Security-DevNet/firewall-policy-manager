// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import '@mantine/core/styles.css';
import './ui/skin.css';

import { MantineProvider } from '@mantine/core';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App';
import { appTheme } from './ui/theme';

const root = document.getElementById('root');
if (root === null) throw new Error('Application root element is missing');

createRoot(root).render(
  <StrictMode>
    <MantineProvider theme={appTheme} defaultColorScheme="dark">
      <App />
    </MantineProvider>
  </StrictMode>,
);
