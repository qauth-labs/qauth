// The Microsoft sign-in plugin (#671, EXPERIMENTAL): a preset on the generic
// upstream OpenID Connect client. The plugin runtime (#600) loads its
// `authMethod` export when AUTH_METHOD_PLUGINS names the package.
import { createMicrosoftMethod } from './lib/microsoft';

export {
  createMicrosoftMethod,
  MICROSOFT_ATTRIBUTES,
  MICROSOFT_ISSUER_TEMPLATE,
  MICROSOFT_LOGIN_ORIGIN,
  MICROSOFT_MULTI_TENANT_ENDPOINTS,
  MICROSOFT_ORIGINS,
  MICROSOFT_PLUGIN_ID,
  MICROSOFT_PLUGIN_TYPE,
  MICROSOFT_SCOPES,
  MICROSOFT_TENANT_ID_PATTERN,
  type MicrosoftConfig,
  microsoftConfigSchema,
  microsoftIssuer,
  microsoftRedirectUri,
} from './lib/microsoft';

/** The plugin's AuthMethod, as the plugin loader imports it. */
export const authMethod = createMicrosoftMethod();
