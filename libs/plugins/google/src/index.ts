// The Google sign-in plugin (#671, EXPERIMENTAL): a preset on the generic
// upstream OpenID Connect client. The plugin runtime (#600) loads its
// `authMethod` export when AUTH_METHOD_PLUGINS names the package.
import { createGoogleMethod } from './lib/google';

export {
  createGoogleMethod,
  GOOGLE_ATTRIBUTES,
  GOOGLE_ISSUER,
  GOOGLE_ORIGINS,
  GOOGLE_PLUGIN_ID,
  GOOGLE_PLUGIN_TYPE,
  GOOGLE_SCOPES,
  type GoogleConfig,
  googleConfigSchema,
  googleRedirectUri,
} from './lib/google';

/** The plugin's AuthMethod, as the plugin loader imports it. */
export const authMethod = createGoogleMethod();
