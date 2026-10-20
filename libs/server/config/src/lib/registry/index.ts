// Configuration key registry exports (ADR-018 §5)
export { type AliasedEnv, applyKeyAliases, KeyAliasConflictError, type RawEnv } from './aliases';
export { type ConfiguredEnv, readConfiguredEnv } from './configured-env';
export { envSchemaShape, findRegistryDrift, type RegistryDrift } from './drift';
export { experimentalSettingWarnings } from './experimental';
export {
  AUTH_SERVER_KEYS,
  CONFIG_KEY_REGISTRY,
  DEVELOPER_PORTAL_KEYS,
  SERVER_CONFIG_KEYS,
} from './keys';
export { CONFIGURATION_PAGE_PATH, describeDefault, renderConfigurationPage } from './page';
export {
  type ConfigKey,
  type ConfigKeyInput,
  type ConfigWarning,
  defineKeys,
  type EnvDeprecationWarning,
  KEY_TIERS,
  type KeyAlias,
  type KeyDefault,
  type KeyOwner,
  type KeyRole,
  type KeyTier,
} from './types';
