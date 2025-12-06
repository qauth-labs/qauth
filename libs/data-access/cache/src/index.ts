export * from './lib/redis';
export * from './lib/utils';

// Export generic cache client type (abstracted from implementation)
export type { CacheClient } from './lib/redis';
