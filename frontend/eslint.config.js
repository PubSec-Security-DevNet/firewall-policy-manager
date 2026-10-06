import eslint from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist',
      'coverage',
      'src/api/schema.d.ts',
      'eslint.config.js',
      'e2e/cdp-release-candidate.mjs',
      'e2e/cdp-route-smoke.mjs',
      'e2e/cdp-application-sweep.mjs',
      'e2e/cdp-function-smoke.mjs',
      'e2e/cdp-fixture-setup.mjs',
      'e2e/cdp-coverage.mjs',
      'e2e/cdp-fault-smoke.mjs',
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-base-to-string': 'off',
      'react-hooks/purity': 'off',
      'react-hooks/set-state-in-effect': 'off',
      'react-refresh/only-export-components': 'off',
    },
  },
  {
    files: ['src/features/**/*.{ts,tsx}', 'src/pages/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@mantine/core',
              message: "Feature and page code must use the semantic UI layer from '../ui'.",
            },
            {
              name: '@mantine/hooks',
              message: 'Feature and page code must use approved application hooks.',
            },
          ],
          patterns: [
            {
              group: ['**/providers/**', '**/*fmc*', '**/*scc*'],
              message: 'Browser code must call the application API, never a provider client.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['src/**/*.test.{ts,tsx}', 'src/test/**/*.{ts,tsx}'],
    languageOptions: { globals: globals.node },
    rules: { 'no-restricted-imports': 'off' },
  },
);
