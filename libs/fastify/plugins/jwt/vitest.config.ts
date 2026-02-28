import path from 'node:path';
import baseConfig from '../../../../vitest.config';
import { mergeConfig } from 'vite';

export default mergeConfig(baseConfig, {
  resolve: {
    alias: {
      '@qauth/shared-errors': path.resolve(__dirname, '../../../shared/errors/src/index.ts'),
      '@qauth/server-jwt': path.resolve(__dirname, '../../../server/jwt/src/index.ts'),
    },
  },
});
