// The Sign in with Apple plugin (#671, EXPERIMENTAL): a preset on the generic
// upstream OpenID Connect client. The plugin runtime (#600) loads its
// `authMethod` export when AUTH_METHOD_PLUGINS names the package.
import { createAppleMethod } from './lib/apple';

export {
  APPLE_ATTRIBUTES,
  APPLE_ISSUER,
  APPLE_ORIGINS,
  APPLE_PLUGIN_ID,
  APPLE_PLUGIN_TYPE,
  APPLE_PRIVATE_RELAY_DOMAIN,
  APPLE_SCOPES,
  type AppleConfig,
  appleConfigSchema,
  appleRedirectUri,
  appleUserName,
  createAppleMethod,
  isApplePrivateRelay,
  MAX_APPLE_NAME_LENGTH,
} from './lib/apple';

/** The plugin's AuthMethod, as the plugin loader imports it. */
export const authMethod = createAppleMethod();
