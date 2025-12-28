export * from './lib/redis';
export * from './lib/utils';

// Export generic cache client type (abstracted from implementation)
export type { CacheClient } from './lib/redis';

// Export data interfaces for type-safe usage
export type { SessionData, UserData } from './lib/utils';
