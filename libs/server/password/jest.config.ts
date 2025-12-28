import { readFileSync } from 'fs';
import { join } from 'path';
import { pathsToModuleNameMapper } from 'ts-jest';

// Use process.cwd() to get the workspace root, then build relative path
const workspaceRoot = process.cwd();
const tsConfigBasePath = join(workspaceRoot, 'tsconfig.base.json');

const tsConfigBase = JSON.parse(readFileSync(tsConfigBasePath, 'utf-8'));
const { compilerOptions } = tsConfigBase;

export default {
  displayName: 'password',
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx'],
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.spec.json' }],
  },
  testMatch: ['**/__tests__/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
  collectCoverageFrom: ['src/**/*.ts', '!src/**/*.d.ts'],
  coverageDirectory: '../../../coverage/libs/server/password',
  moduleNameMapper: pathsToModuleNameMapper(compilerOptions.paths || {}, {
    prefix: '<rootDir>/../../../',
  }),
};
