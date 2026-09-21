import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.VITE_API_PROXY_TARGET ?? 'http://backend:8000',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    maxWorkers: 1,
    setupFiles: ['./src/test/setup.ts'],
  },
});
