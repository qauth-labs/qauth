import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import { cachePlugin } from '@qauth-labs/fastify-plugin-cache';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { dpopPlugin } from '@qauth-labs/fastify-plugin-dpop';
import { egressPlugin, type EgressPluginOptions } from '@qauth-labs/fastify-plugin-egress';
import { emailPlugin, type EmailProviderConfig } from '@qauth-labs/fastify-plugin-email';
import { type DeliveryRoute, eventDeliveryPlugin } from '@qauth-labs/fastify-plugin-event-delivery';
import {
  assertAttestingIssuersUsable,
  assertCredentialStatusConfigUsable,
  assertEmailVerifyingIssuersUsable,
  assertTrustedIssuersUsable,
  createConfiguredProviders,
  credentialStatusProvisioningOf,
  federationPlugin,
  keyStorageAssuranceProvisioningOf,
  type VerifierCryptoCapabilities,
} from '@qauth-labs/fastify-plugin-federation';
import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import { passwordPlugin } from '@qauth-labs/fastify-plugin-password';
import { pkcePlugin } from '@qauth-labs/fastify-plugin-pkce';
import { sessionServicePlugin } from '@qauth-labs/fastify-plugin-sessions';
import {
  createRepositoryPublishedKeyReader,
  signerPlugin,
} from '@qauth-labs/fastify-plugin-signer';
import { SSF_DELIVERY_KIND, ssfPlugin } from '@qauth-labs/fastify-plugin-ssf';
import {
  resolveStatusListTrustAnchorPems,
  resolveVerifierCertificateChainPems,
  resolveVerifierSigningKeyPem,
} from '@qauth-labs/server-config';
import type { FastifyInstance, RouteOptions } from 'fastify';

import { env } from '../config/env';
import { logExperimentalFeatures } from '../config/experimental-features';
import { type AdminApiOptions, installAdminApi } from './admin/listener';
import { publicRouteProblem } from './admin/route-placement';
import { deriveCryptoCapabilities } from './crypto-capabilities';
import { ADMIN_ROLE_CATALOG } from './helpers/admin-roles';
import { assertSubjectResolutionProvisioned } from './helpers/assert-subject-resolution';
import { type DefaultRealmBootSettings, emailBaseUrlWarning } from './helpers/default-realm-boot';
import { verifyResourceRequestProof } from './helpers/dpop';
import type { EventLogQueueLimits } from './helpers/event-log-queue';
import {
  createEventTelemetry,
  type EventTelemetry,
  eventTelemetrySettings,
} from './helpers/event-telemetry';
import { keyVariableSettings, kidlessTokenKeyIds } from './helpers/key-variables';
import { oid4vpResponseKeySecret } from './helpers/oid4vp-response-key';
import type { RealmHostLookup } from './helpers/realm-host-cache';
import { realmIssuer, tokenRealm } from './helpers/realm-url';
import { requestRealm } from './helpers/request-realm';
import { isJtiRevoked } from './helpers/token-revocation';
import { createUnavailableSigner } from './helpers/unavailable-signer';
import { provisionedVerifierMaterial } from './helpers/verifier-identity';
import { defaultRealmPlugin } from './plugins/default-realm';
import errorHandler from './plugins/error-handler';
import { jobsPlugin } from './plugins/jobs';
import { metricsPlugin } from './plugins/metrics';
import { rateLimitPlugin } from './plugins/rate-limit';
import { realmResolverPlugin } from './plugins/realm-resolver';
import { requestIdPlugin } from './plugins/request-id';
import { securityHeadersPlugin } from './plugins/security-headers';
import { routeModulesFor } from './route-manifest';
import {
  checkServiceRoles,
  describeServiceRoles,
  holdsSigner,
  pluginsFor,
  repositoriesFor,
  routeRolesProblem,
  servesAdminListener,
  ServiceRoleBootError,
} from './service-roles';

/**
 * What this deployment's crypto layer can do, handed to the VerifierProfile gate
 * (#299) so a profile is checked against REALITY rather than against its own
 * declaration.
 *
 * Without this, `haip-1.0`'s `signingAlgs: ['ES256']` and
 * `responseEncryption: 'required'` (HAIP §7 / §5.1) were declared and enforced
 * nowhere: the only thing keeping that profile out was its missing certificate
 * chain, so the moment #233 provisioned one it would have booted on an
 * EdDSA-only stack and every EUDI wallet would have rejected every request.
 *
 * The answer is DERIVED from the deployment's provisioned key material rather
 * than written here, because the two questions "does the crypto library export
 * this algorithm" and "can this deployment sign with it" are not the same
 * question, and only the second one is what the gate is asking. See
 * `./crypto-capabilities` for which key material each entry is derived from,
 * and why response encryption — which needs no operator key — is the one entry
 * answered by the build rather than by the configuration (#377 Phase C).
 *
 * The token keys are the default realm's, as its key store holds them (#491),
 * never the key variables. `tokenSigningAlgorithms` names the algorithms of its
 * active `token_signing` keys.
 */
function cryptoCapabilities(tokenSigningAlgorithms: readonly string[]): VerifierCryptoCapabilities {
  return deriveCryptoCapabilities({
    tokenSigningAlgorithms,
    // The OID4VP verifier's own key and chain (#377). Read here as CONFIGURED
    // rather than as validated: validation happens inside `app()` below and is a
    // boot refusal, so a deployment that reaches a request with this descriptor
    // has already had its chain accepted.
    verifierEs256PrivateKey: resolveVerifierSigningKeyPem(env),
    verifierCertificateChainPems: resolveVerifierCertificateChainPems(env),
  });
}

/**
 * The token algorithms the gate is first checked against, while the server
 * registers: the key boot step, which runs when the server is ready, leaves
 * the default realm an active EdDSA `token_signing` key or refuses to start
 * (`provisionRealmKeys`). Once it has run, the gate is checked again against
 * the keys the store holds.
 */
const BOOT_TOKEN_SIGNING_ALGORITHMS: readonly string[] = Object.freeze(['EdDSA']);

/**
 * The settings the default realm's boot step (#484) reads, from the
 * environment. Exported for the E2E harness, which runs the step again after
 * it empties the database.
 */
export function defaultRealmBootSettings(): DefaultRealmBootSettings {
  return {
    realmName: env.DEFAULT_REALM_NAME,
    jwtIssuer: env.JWT_ISSUER,
    endpointHosts: env.DEFAULT_REALM_ENDPOINT_HOSTS,
    // The passkey RP ID (#467): checked against the realm's lock at every
    // boot, whatever WEBAUTHN_ENABLED says.
    passkeys: {
      rpId: env.WEBAUTHN_RP_ID,
      allowParentDomainRpId: env.WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN,
    },
  };
}

/** Options for {@link app}. */
export interface AppOptions {
  /**
   * Run the boot steps that need the database when the server is ready: the
   * default realm's (#484) and its keys' (#485). On unless set to `false`,
   * which only a boot with no database does: the OpenAPI export and the
   * error-handler wiring test.
   */
  defaultRealmBoot?: boolean;
  /**
   * How the realm resolver (#486) finds the realm of a request host. The
   * database's `realm_hosts` unless set, which only a boot with no database
   * does: the error-handler wiring test and the route class test.
   */
  realmLookup?: RealmHostLookup;
  /**
   * The event telemetry queue's sizes and times (#541), for a suite that
   * fills the queue or waits for a batch. The defaults unless set.
   */
  eventTelemetryLimits?: Partial<EventLogQueueLimits>;
  /**
   * Event delivery routes beside the server's own (#460): the SSF route
   * while SSF_TRANSMITTER_ENABLED is on (#410), and the webhook route once it
   * lands (#538). A suite that watches the role passes a route of its own.
   */
  eventDeliveryRoutes?: readonly DeliveryRoute[];
  /**
   * TEST SUPPORT — builds the egress client (#481) instead of the production
   * one: a suite passes `createTestEgressClient` to reach a local fixture
   * server. The egress plugin refuses it unless NODE_ENV is `test`, and
   * `main.ts` never sets it.
   */
  egressClientFactory?: EgressPluginOptions['createClient'];
  /**
   * The admin listener (ADR-019 Decision 7, #511): the Fastify instance
   * `createAdminServer` built, on which the app installs the admin API once
   * its own plugins are registered (`admin/listener.ts`), and which it closes
   * when it closes. `main.ts` passes one when the process holds the `admin`
   * role and ADMIN_API_ENABLED is on; the app refuses one otherwise. Its
   * other members are test support.
   */
  adminListener?: AdminApiOptions & { readonly server: FastifyInstance };
}

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The OpenTelemetry log export of events (#541), present only when
     * OTEL_EVENTS_ENABLED is on.
     */
    eventTelemetry?: EventTelemetry;
  }
}

/**
 * The credential-provider registry and the wallet configuration's boot checks,
 * for a process whose roles sign users in (#495: `web` and `api`).
 *
 * @param defaultRealmBoot - whether the boot steps that need the database run,
 *   and with them the gate's second check against the stored token keys
 */
async function registerFederation(
  fastify: FastifyInstance,
  defaultRealmBoot: boolean
): Promise<void> {
  // Credential-provider registry (ADR-003, #228). The bootstrap remains the
  // single registration point, but WHICH providers exist is now a pure function
  // of config (`createConfiguredProviders`) so the decision is unit-testable
  // without booting this app. Adding an upstream still means extending that
  // list, never touching routes.
  //
  // WalletProvider (ADR-004, #232) joins the set only when
  // WALLET_FEDERATION_ENABLED is on — default OFF while epic #231 (#233–#238)
  // is incomplete, and inert even when on, because the skeleton's methods fail
  // closed and nothing resolves 'wallet' yet.
  //
  // Turning the flag on additionally requires a VerifierProfile (#299): the flag
  // decides WHETHER the wallet provider exists, the profile decides WHAT POSTURE
  // it runs with. An enabled deployment carrying no profile — one whose Client
  // Identifier Prefix needs unprovisioned X.509 material, or one whose declared
  // signing/encryption mandates exceed `cryptoCapabilities` above — throws here
  // and refuses to boot, rather than serving wallet flows with an unstated or
  // unmeetable posture.
  // Issuer trust (#236), the OTHER trust direction: which credential ISSUERS a
  // realm accepts credentials from. `OID4VP_TRUSTED_ISSUERS` is validated by
  // the env schema for SHAPE, but the runtime additionally canonicalizes every
  // entry, and a per-realm allowlist is all-or-nothing — so a single entry the
  // canonicalizer refuses (userinfo, a query string, a fragment) would make
  // that realm trust NOBODY, with no boot failure and no log, and every
  // Verifiable Presentation to it rejected. This runs the runtime's own
  // reduction at startup so that configuration fails the boot instead.
  //
  // NOT gated on WALLET_FEDERATION_ENABLED: the typo is a typo whether or not
  // wallet flows are switched on today, and finding it at boot beats finding it
  // when the first presentation arrives.
  assertTrustedIssuersUsable(env.OID4VP_TRUSTED_ISSUERS);

  // `OID4VP_EMAIL_VERIFYING_ISSUERS` (ANT-2026-BGP7XCR2), the same posture: an
  // entry the canonicalizer refuses would vouch for nobody, and that issuer's
  // users would silently lose their `email` claim.
  assertEmailVerifyingIssuersUsable(env.OID4VP_EMAIL_VERIFYING_ISSUERS);

  // Credential revocation (#297/#378), the same posture as the line above and
  // for the same reason. The two OID4VP_STATUS_LIST_* variables are validated by
  // the env schema for SHAPE, but the runtime additionally PARSES every anchor
  // certificate and COMPILES every URI prefix — and a deployment that configured
  // one half and not the other would build a checker that silently refuses every
  // credential carrying a `status` claim. Running the runtime's own compilation
  // at startup is what turns both into a boot failure instead of a 100%
  // login-failure rate nobody can explain.
  //
  // NOT gated on WALLET_FEDERATION_ENABLED or on the selected profile: a typo is
  // a typo whether or not wallet flows are switched on today.
  const statusListTrustAnchorPems = resolveStatusListTrustAnchorPems(env);
  assertCredentialStatusConfigUsable({
    trustAnchorPems: statusListTrustAnchorPems,
    uriAllowlist: env.OID4VP_STATUS_LIST_URI_ALLOWLIST,
    ...(env.OID4VP_STATUS_LIST_SIGNERS === undefined
      ? {}
      : { signerDelegations: env.OID4VP_STATUS_LIST_SIGNERS }),
  });

  // The VERIFIER identity (#377), and the same posture again for the third
  // trust direction: the two calls above validate material QAuth will BELIEVE,
  // this one validates the material QAuth will PRESENT. It parses the chain,
  // checks it terminates at a configured anchor with the anchor itself excluded,
  // and confirms the signing key belongs to the leaf — every one of which is an
  // operator mistake whose only runtime symptom is a wallet rejecting 100% of
  // requests with nothing in QAuth's logs naming the cause.
  //
  // NOT gated on WALLET_FEDERATION_ENABLED, for the reason the two gates above
  // give: a mis-pasted certificate is mis-pasted whether or not wallet flows are
  // switched on today, and finding it at boot beats finding it on the first
  // presentation. A deployment that configured nothing gets `undefined` and is
  // unaffected.
  //
  // The call also produces the marker set both boot gates below read. #379
  // introduced that as a module-level `PROVISIONED_VERIFIER_MATERIAL = undefined`
  // with the note "replace `undefined` here, not at either call site" —
  // precisely so the subject-resolution gate and the provider gate could never
  // disagree about which profiles resolve. This is that replacement, widened:
  // the two request-path callers of `resolveVerifierProfile` read the SAME
  // helper, so the boot gates and the request path cannot disagree either.
  //
  // A call rather than a module-level constant because the material is now
  // VALIDATED, and validation can throw: computing it at module scope would turn
  // an operator's mis-pasted certificate into an import-time crash with no
  // plugin context around it. The helper memoises, so this parses the chain once
  // per process however many times it is asked.
  const provisioned = provisionedVerifierMaterial();

  // Attesting issuers (#308/#379), the same posture again. `server-config`
  // validates each key as a syntactically valid https:// URL; the runtime
  // additionally reduces it with `canonicalizeIssuerIdentifier`, which refuses
  // userinfo, a query string and a fragment. The resolver that would catch the
  // disagreement is built lazily at the first presentation, so without this the
  // symptom is silent: every credential from that ecosystem resolves to
  // `assurance: 'none'`, and a policy entry demanding hardware key storage
  // grants `'low'` to a wallet that satisfies it.
  //
  // NOT gated on WALLET_FEDERATION_ENABLED, for the reason given twice above.
  assertAttestingIssuersUsable(env.OID4VP_ATTESTING_ISSUERS);

  // The at-rest secret for the per-request `direct_post.jwt` decryption key
  // (#377 Phase C), the same posture once more. `OID4VP_RESPONSE_KEY_SECRET` is
  // OPTIONAL — unset stores the key in the clear, which is the default — but a
  // value that is set and does not decode to exactly one AES-256 key is a
  // misconfiguration whose only runtime symptom would be every wallet sign-in
  // failing at the moment the request state is written. The helper memoises,
  // so this is the one decode the process ever performs.
  //
  // NOT gated on WALLET_FEDERATION_ENABLED or on the selected profile, for the
  // reason given repeatedly above: a mis-pasted secret is mis-pasted whether or
  // not the profile that would use it is selected today.
  oid4vpResponseKeySecret();

  // Subject resolution (#300/#238/#379, ADR-010 §6), the fourth gate in this
  // group and the one that IS flag-gated. #300 and #238 each deferred it "to
  // the first consumer"; the wallet login path is now that consumer, so a
  // deployment whose `OID4VP_SUBJECT_*` configuration cannot build a strategy
  // fails here instead of refusing every presentation with an error nobody
  // reads. It runs BEFORE `createConfiguredProviders` below but yields to it on
  // a profile that cannot resolve at all, so a profile refusal keeps its own
  // message. Nothing about the request path changes — see the helper.
  assertSubjectResolutionProvisioned(env, provisioned);

  const providerSettings = {
    walletFederationEnabled: env.WALLET_FEDERATION_ENABLED,
    verifierProfileId: env.OID4VP_VERIFIER_PROFILE,
    // What the operator provisioned for revocation checking (#297). A profile
    // declaring `requireCredentialStatus: true` — `haip-1.0` does — refuses to
    // start when either half is missing, naming which one. Threaded rather
    // than defaulted: the default is the refusing value, and a bootstrap that
    // HAS the answer must state it.
    credentialStatusProvisioned: credentialStatusProvisioningOf({
      trustAnchorPems: statusListTrustAnchorPems,
      uriAllowlist: env.OID4VP_STATUS_LIST_URI_ALLOWLIST,
    }),
    // What the operator provisioned for key-storage assurance (#308/#379). A
    // profile declaring `keyStorageAssurance: 'required'` — `haip-1.0` does —
    // refuses to start unless something can establish it. Before #379 this
    // option was never passed, so `assertKeyStorageAssuranceProvisioned` sat
    // permanently in its refusing state: a constant, not a predicate.
    //
    // Only the TRANSITIVE path is provisionable today. The direct path
    // (verifying an Appendix D attestation conveyed into the presentation)
    // needs the same certificate surface #233 owes the line below.
    keyStorageAssuranceProvisioned: keyStorageAssuranceProvisioningOf(env.OID4VP_ATTESTING_ISSUERS),
    // What the operator provisioned for the VERIFIER identity (#377) — the
    // ES256 key and the X.509 chain a wallet establishes QAuth's identity
    // from. Derived from the material that VALIDATED above rather than from
    // the raw variables, so the marker set the gate reads can never claim a
    // capability the chain did not earn: a chain that failed to anchor took
    // the boot down before this line, and a deployment that configured
    // nothing yields `NO_VERIFIER_MATERIAL`, which is what makes a profile
    // requiring a WRPAC refuse.
    provisionedVerifierMaterial: provisioned,
  };
  await fastify.register(federationPlugin, {
    providers: createConfiguredProviders({
      ...providerSettings,
      cryptoCapabilities: cryptoCapabilities(BOOT_TOKEN_SIGNING_ALGORITHMS),
    }),
  });
  // The gate again, once the key boot step has run (its hook is earlier):
  // against the token algorithms of the default realm's stored keys (#491),
  // which refuses the boot when they cannot meet the profile. A process
  // without the signer role reads them from the published keys (#495).
  if (defaultRealmBoot) {
    fastify.addHook('onReady', async () => {
      const realm = await fastify.repositories.realms.findByName(env.DEFAULT_REALM_NAME);
      if (realm === undefined) {
        throw new Error(`The default realm "${env.DEFAULT_REALM_NAME}" does not exist`);
      }
      const keys = await fastify.signer.getVerificationKeys('local', realm.id, 'token_signing');
      createConfiguredProviders({
        ...providerSettings,
        cryptoCapabilities: cryptoCapabilities(
          keys.filter((key) => key.status === 'active').map((key) => key.algorithm)
        ),
      });
    });
  }
}

/** The mail service, for a process whose roles send mail (#495: `api`). */
async function registerEmail(fastify: FastifyInstance): Promise<void> {
  // Configure email provider from environment variables
  const emailProvider = env.EMAIL_PROVIDER;

  // Build provider-specific configuration
  let providerConfig: EmailProviderConfig | undefined;
  if (emailProvider === 'resend') {
    if (!env.RESEND_API_KEY) {
      throw new Error(
        'RESEND_API_KEY is required when EMAIL_PROVIDER is "resend". Please set it in your environment variables.'
      );
    }
    providerConfig = {
      apiKey: env.RESEND_API_KEY,
      fromAddress: env.EMAIL_FROM_ADDRESS,
    };
  } else if (emailProvider === 'smtp') {
    if (!env.SMTP_HOST || !env.SMTP_PORT || !env.SMTP_USER || !env.SMTP_PASSWORD) {
      throw new Error(
        'SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASSWORD are required when EMAIL_PROVIDER is "smtp". Please set them in your environment variables.'
      );
    }
    providerConfig = {
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: env.SMTP_SECURE,
      auth: {
        user: env.SMTP_USER,
        pass: env.SMTP_PASSWORD,
      },
      fromAddress: env.EMAIL_FROM_ADDRESS,
    };
  }
  // For 'mock' provider, providerConfig is undefined (no config needed)

  // EMAIL_BASE_URL is optional and no longer read (#490). Say so when it is
  // set to another base than the default realm's issuer, where the links went.
  const emailBaseUrlIgnored = emailBaseUrlWarning(env.EMAIL_BASE_URL, env.JWT_ISSUER);
  if (emailBaseUrlIgnored !== undefined) {
    fastify.log.warn(
      { variable: 'EMAIL_BASE_URL', value: env.EMAIL_BASE_URL, issuer: env.JWT_ISSUER },
      emailBaseUrlIgnored
    );
  }

  await fastify.register(emailPlugin, {
    provider: emailProvider,
    providerConfig,
    serviceConfig: {
      defaultFrom: env.EMAIL_FROM_ADDRESS,
      // No link base here: a mail's links start at the issuer of the realm
      // the account belongs to, passed with each mail (ADR-019 Decision 1,
      // #490). EMAIL_BASE_URL is no longer read.
      // Same value the send routes use to compute `expiresAt`, so the copy in
      // the email cannot drift from the lifetime actually enforced (#334).
      verificationTokenExpiry: env.EMAIL_VERIFICATION_TOKEN_EXPIRY,
    },
  });
}

/**
 * The JWT plugin, for a process whose roles issue or verify tokens (#495:
 * `web` and `api`).
 */
async function registerJwt(fastify: FastifyInstance): Promise<void> {
  // Tokens (ADR-019 Decisions 1 and 9, #491). The plugin holds no key: every
  // access, ID and hybrid token is signed through the signer with the keys of
  // its realm, which names the realm's issuer as `iss` and its key as `kid`,
  // and every token is verified with the keys the signer lists for the
  // request's realm, under that realm's issuer. The key variables reach only
  // the key boot step, on a process that holds the signer.
  //
  // A process without the signer role (#495) holds no key at all: its signer
  // refuses every signature with 503, and lists the realm's verification keys
  // from the published public keys, so it still verifies tokens.
  await fastify.register(jwtPlugin, {
    signer: fastify.signer,
    requestRealm: (request) => tokenRealm(requestRealm(request)),
    accessTokenLifespan: env.ACCESS_TOKEN_LIFESPAN,
    refreshTokenLifespan: env.REFRESH_TOKEN_LIFESPAN,
    // A token issued before tokens named their key (#491) carries no `kid`:
    // it is tried only against the Ed25519 key the key variable holds, which
    // signed it, never against a key the store generated. Transitional.
    kidlessKeyIds: await kidlessTokenKeyIds(env),
    // RFC 7009 revocation: the shared `requireJwt` preHandler consults this
    // Redis-backed denylist after verification so a revoked access token is
    // rejected everywhere it is used as a bearer credential. Resolved lazily
    // via the `fastify.redis` decorator (cache plugin registered above).
    isTokenRevoked: (jti) => isJtiRevoked(fastify, jti),
    // RFC 9449 §7 (#480): with DPoP on, `requireJwt` also accepts
    // `Authorization: DPoP <token>` for a DPoP-bound token, and this checks the
    // request's proof. Off, a `DPoP` header is no credential, as before. A
    // DPoP-bound token sent as a Bearer token is refused either way (§7.2).
    ...(fastify.dpop
      ? {
          verifyDpopProof: (request, token, claims) =>
            verifyResourceRequestProof(fastify, request, token, claims),
        }
      : {}),
    // ADR-005: when hybrid signing is enabled, mint live hybrid access tokens
    // (#275) with the realm's hybrid pair. The key boot step refuses to start
    // a deployment whose realm holds half a pair; the plugin refuses to start
    // when SIGNING_ALGORITHM_MODE does not enable ML-DSA-65. Default OFF.
    //
    // #248 F7/F11: the plugin resolves the ML-DSA backend through
    // `getSignatureBackend`, so it must see the operator's SIGNING_ALGORITHM_MODE
    // allowlist rather than a hardcoded literal.
    hybridSigningEnabled: env.HYBRID_SIGNING_ENABLED,
    enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
  });
}

export async function app(fastify: FastifyInstance, opts: AppOptions) {
  const {
    defaultRealmBoot = true,
    realmLookup,
    eventTelemetryLimits,
    eventDeliveryRoutes,
    egressClientFactory,
    adminListener,
  } = opts;

  // The service roles (ADR-019 Decision 8, #495): which routes, plugins,
  // repositories and jobs this process registers. Checked before anything
  // else, so a process that must hold no key refuses to boot before it reads
  // one, naming each variable at fault.
  const roles = env.SERVICE_ROLES;
  const roleCheck = checkServiceRoles(env, process.env);
  if (roleCheck.problems.length > 0) {
    throw new ServiceRoleBootError(roleCheck.problems);
  }
  for (const warning of roleCheck.warnings) {
    fastify.log.warn({ variable: warning.variable }, warning.message);
  }
  const plugins = pluginsFor(roles);

  // The route modules of this process's roles, imported now, all at once and
  // while the plugins below register. avvio gives a plugin only what is left
  // of this plugin's start-up time (`pluginTimeout`), so importing them one by
  // one at the routes would spend it under load. A rejection is awaited below;
  // the catch only keeps it from counting as unhandled if the boot fails first.
  const routeModules = Promise.all(
    routeModulesFor(roles).map(async (entry) => ({ entry, plugin: (await entry.load()).default }))
  );
  routeModules.catch(() => undefined);

  // Every route of the app names the roles that register it (#495): the route
  // manifest tags its modules' routes below, and the check after them refuses
  // to boot when a route registered here has no role. @fastify/cors's
  // `OPTIONS *` belongs to every role this process holds. Collected from the
  // first plugin on, so no route escapes the check.
  const registeredRoutes: RouteOptions[] = [];
  fastify.addHook('onRoute', (route) => {
    if (
      route.config?.serviceRoles === undefined &&
      route.method === 'OPTIONS' &&
      route.url === '*'
    ) {
      route.config = { ...route.config, serviceRoles: roles };
    }
    registeredRoutes.push(route);
  });

  fastify.log.info(
    { serviceRoles: describeServiceRoles(roles), plugins: [...plugins] },
    'Starting the service roles'
  );

  // ADR-018 §5: an experimental feature may change in a minor release, so a
  // deployment that turns one on is told so at every boot: one `warn` line per
  // item, with its id and docs link. Logged here rather than in `main.ts`, so
  // every boot of the app, a test harness's included, says it.
  logExperimentalFeatures(fastify.log);

  // The OpenTelemetry log export of events (ADR-018 §3, #541), before the
  // database: the event store hands each event to it once the event's
  // transaction commits. Off by default, and then no exporter exists. It
  // sends what is queued, for a few seconds at most, when the server closes.
  const eventTelemetry = createEventTelemetry(eventTelemetrySettings(env), {
    log: fastify.log,
    ...(eventTelemetryLimits === undefined ? {} : { limits: eventTelemetryLimits }),
  });
  if (eventTelemetry !== undefined) {
    fastify.decorate('eventTelemetry', eventTelemetry);
    fastify.addHook('onClose', () => eventTelemetry.shutdown());
  }

  await fastify.register(databasePlugin, {
    eventTelemetry,
    // Only the repositories this process's roles use (#495): reading another
    // throws, naming it.
    repositories: repositoriesFor(roles),
    // The admin permission catalog and built-in roles (#507), which every
    // admin role and grant write is checked against (#510).
    adminRoleCatalog: ADMIN_ROLE_CATALOG,
    // Realm policies the environment seeds into a new realm (ADR-019
    // Decision 10): the realm row owns them once it exists (#536).
    realmPolicySeeds: {
      userEventRetentionDays: env.EVENT_RETENTION_USER_DAYS,
      adminEventRetentionDays: env.EVENT_RETENTION_ADMIN_DAYS,
    },
    config: {
      connectionString: env.DATABASE_URL,
      pool: {
        max: env.DB_POOL_MAX,
        min: env.DB_POOL_MIN,
        idleTimeoutMillis: env.DB_POOL_IDLE_TIMEOUT,
        connectionTimeoutMillis: env.DB_POOL_CONNECTION_TIMEOUT,
      },
    },
  });

  // The default realm's boot step (ADR-019 Decision 1, #484): find or create
  // the realm named DEFAULT_REALM_NAME, give it its issuer and primary host
  // from JWT_ISSUER, mark it the operator realm when there is none, and add
  // DEFAULT_REALM_ENDPOINT_HOSTS. It runs in an `onReady` hook, so before the
  // server listens, and refuses the boot when the stored issuer differs from
  // JWT_ISSUER, or the realm's passkeys are bound to another RP ID. Registered right after the database so its hook runs before
  // the job runner starts.
  if (defaultRealmBoot) {
    await fastify.register(defaultRealmPlugin, defaultRealmBootSettings());
  }

  // The signer's wiring (ADR-019 Decision 9, #464). The plugin loads the KEK:
  // NODE_ENV=production refuses to start without one. Every token is signed
  // through it, with the keys of the request's realm (#491), so it registers
  // on every boot of a process that holds the signer; it reads nothing until
  // the first signature.
  //
  // With the database steps on, it also runs the default realm's key boot
  // step (#485). Its `onReady` hook runs after the default realm's, which
  // creates the realm: under the realm's key lock it imports each key variable
  // the realm's encrypted store lacks, creates the standard keys still missing
  // (an RS256 signing key too on a fresh deployment), and warns about every key
  // variable still set. A signing variable that holds a new key replaces the
  // stored key until rotation through the store ships (#544, #551); otherwise
  // tokens never read the variables. The session cookie keeps its variable
  // until it moves onto the signer (#493).
  //
  // Only a process that holds the `signer` role loads it (#495). Any other
  // holds no KEK and no key: its `fastify.signer` refuses every signature,
  // encryption and secret with 503 until it can call the signer service
  // (#497), and reads the realm's verification keys and JWKS from the
  // published public keys, which need neither.
  if (holdsSigner(roles)) {
    await fastify.register(signerPlugin, {
      db: fastify.db,
      kekEnv: process.env,
      enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
      hybridSigning: env.HYBRID_SIGNING_ENABLED,
      ...(defaultRealmBoot
        ? {
            realmKeysBoot: {
              realmName: env.DEFAULT_REALM_NAME,
              environmentKeys: keyVariableSettings(env, process.env),
            },
          }
        : {}),
    });
  } else {
    fastify.decorate(
      'signer',
      createUnavailableSigner(
        env.SIGNER_URL,
        createRepositoryPublishedKeyReader(fastify.repositories.realmPublicKeys)
      )
    );
  }

  // Request-id propagation (#128), ahead of the realm resolver below: both
  // are `onRequest` hooks of this scope and run in registration order, so a
  // 421 the resolver throws still echoes the request id an operator needs to
  // find its reason in the log.
  await fastify.register(requestIdPlugin);

  // Realm resolution by host (ADR-019 Decision 1, #486). Every request but a
  // `none` route's finds its realm through the host it names, or gets 421.
  // This position IS load-bearing, for the rate limiter's reason below: the
  // plugin checks each route's `config.surface` in an `onRoute` hook, which is
  // not retroactive, so it must load before any route, @fastify/cors's
  // `OPTIONS *` included. Its `onRequest` hook belongs to this scope, so it
  // runs before every route's own hooks, the rate limiter's among them,
  // wherever the limiter is registered: a refused host is never counted, and
  // a per-realm limit can read `request.realm`.
  await fastify.register(realmResolverPlugin, {
    ...(realmLookup === undefined ? {} : { lookup: realmLookup }),
  });

  await fastify.register(cachePlugin, {
    config: {
      url: env.REDIS_URL,
      host: env.REDIS_HOST,
      port: env.REDIS_PORT,
      password: env.REDIS_PASSWORD,
      db: env.REDIS_DB,
      maxRetriesPerRequest: env.REDIS_MAX_RETRIES,
      connectTimeout: env.REDIS_CONNECTION_TIMEOUT,
      commandTimeout: env.REDIS_COMMAND_TIMEOUT,
      lazyConnect: true,
    },
  });

  // The SSRF-safe egress client (ADR-019 Decision 8, #481): `fastify.egress`,
  // over the deployment allowlist that EGRESS_ALLOWLIST_PATH names, read once
  // here. Every outbound call the routes make for a configuration value or a
  // request — CIMD documents, client and issuer JWKS, ID-JAG discovery — goes
  // through it, naming who set the destination. The list lives only in that
  // file: not in the database, and no route reads or edits it.
  //
  // A process registers it when its routes make such a call (#495): the
  // route manifest names `egress` for each module that reaches it.
  if (plugins.has('egress')) {
    await fastify.register(egressPlugin, {
      ...(env.EGRESS_ALLOWLIST_PATH === undefined
        ? {}
        : { allowlistPath: env.EGRESS_ALLOWLIST_PATH }),
      ...(egressClientFactory === undefined ? {} : { createClient: egressClientFactory }),
    });
  }

  // DPoP-bound tokens (RFC 9449; ADR-014 §3, ADR-017 phase F3, #480): the
  // shared verifier over the cache plugin's Redis, which records used proofs.
  // `fastify.dpop` is null while DPOP_ENABLED is off, and then no route reads
  // a `DPoP` header. A proof's `htu` is compared with the issuer URL (path
  // included) of the request's realm and the request path, the endpoint URL
  // that realm's discovery publishes (ADR-019 Decision 1, #490), never the
  // `Host` header. A request to one of the realm's endpoint hosts must
  // therefore name the published URL in `htu` too.
  if (plugins.has('dpop')) {
    await fastify.register(dpopPlugin, {
      enabled: env.DPOP_ENABLED,
      baseUrl: (request) => realmIssuer(requestRealm(request)),
    });
  }

  if (plugins.has('password')) {
    await fastify.register(passwordPlugin, {
      hashConfig: {
        memoryCost: env.PASSWORD_MEMORY_COST,
        timeCost: env.PASSWORD_TIME_COST,
        parallelism: env.PASSWORD_PARALLELISM,
        // Client-secret checks beyond this many waiting Argon2 jobs are shed
        // with 503 and `Retry-After` (#751); see `helpers/client-auth.ts`.
        queueLimit: env.PASSWORD_HASH_QUEUE_LIMIT,
      },
      validationConfig: {
        minScore: env.PASSWORD_MIN_SCORE,
      },
    });
  }

  if (plugins.has('pkce')) {
    await fastify.register(pkcePlugin);
  }

  if (plugins.has('federation')) {
    await registerFederation(fastify, defaultRealmBoot);
  }

  if (plugins.has('email')) {
    await registerEmail(fastify);
  }

  if (plugins.has('jwt')) {
    await registerJwt(fastify);
  }

  // Rate limiting (T3). This position IS load-bearing: it MUST stay ahead of
  // the routes of the manifest below. @fastify/rate-limit applies both the global
  // ceiling and every per-route `config.rateLimit` override through an
  // `onRoute` hook, and `onRoute` is NOT retroactive — Fastify fires it as each
  // route is added, so routes already registered by the time this plugin loads
  // are simply never seen. Moving it after the routes would not throw, warn
  // or fail a boot check; it would silently drop every per-route limit,
  // including the brute-force ceiling on /auth/login and the
  // `config: { rateLimit: false }` scrape exemption on /metrics.
  await fastify.register(rateLimitPlugin);

  // Security headers (issue #113): every response — including the
  // server-rendered login/consent pages and error responses — carries the CSP,
  // HSTS, frame-options and related hardening headers.
  //
  // Unlike the rate limiter above, this position is NOT load-bearing (#365) —
  // but for a different reason than the symmetry suggests, and the distinction
  // is the whole point. The plugin installs an `onSend` hook, and `addHook`
  // for that class of hook recurses into already-created child scopes
  // (`this[kChildren].forEach(child => _addHook.call(child, name, fn))` in
  // Fastify's `_addHook`), so it does reach routes that loaded earlier.
  // `onRoute` is explicitly routed past that recursion — which is exactly why
  // the rate limiter above IS position-sensitive and this is not. Do not
  // generalise "hooks are retroactive" from this comment; it holds per hook
  // type, not per plugin.
  await fastify.register(securityHeadersPlugin);

  // Observability (T3): the metrics registry (#123/#126). Its position is not
  // load-bearing either (#365): it only `decorate()`s the instance — its sole
  // consumer, GET /metrics, dereferences `fastify.metrics` inside the handler
  // at request time, not while the route plugin is loading. Request-id
  // propagation (#128) is registered above, ahead of the realm resolver.
  await fastify.register(metricsPlugin);

  // The Shared Signals Framework transmitter (ADR-018 §3, #410). Off by
  // default: `fastify.ssf` is null, no SSF route registers below, and the
  // delivery role gets no SSF route, so no SSF delivery row is ever written.
  // On, it builds the push route over the stream repository and the egress
  // client; the routes, the metadata and the deliveries then serve each realm
  // whose own switch is on.
  //
  // A process registers it when its roles serve the SSF routes (`api`) or
  // deliver (`delivery`, #495); `ssf` is the transmitter, or null.
  if (plugins.has('ssf')) {
    await fastify.register(ssfPlugin, { enabled: env.SSF_TRANSMITTER_ENABLED });
  }
  const ssf = plugins.has('ssf') ? fastify.ssf : null;
  const deliveryRoutes: readonly DeliveryRoute[] = [
    ...(ssf === null ? [] : [ssf.deliveryRoute]),
    ...(eventDeliveryRoutes ?? []),
  ];

  // Background jobs (ADR-019 Decision 8): purge-expired and the SSF subject
  // sweep (#540) on `api`, and event retention (#536) on `delivery`, which
  // reads the delivery routes' enabled
  // destinations and falls back to the retention seeds for a realm whose row
  // is gone. A process builds and runs only the jobs of its roles (#495).
  // With the SSF transmitter off no node serves `ssf`, so an SSF position or
  // delivery left from when it was on holds no event back. The runner starts
  // on `onReady` and stops on `onClose`, so it needs the database and metrics
  // plugins above it; it registers no route, so nothing below depends on its
  // position.
  await fastify.register(jobsPlugin, {
    roles,
    deliveryRoutes,
    unservedDeliveryKinds: ssf === null ? [SSF_DELIVERY_KIND] : [],
    eventRetentionFallback: {
      userEventRetentionDays: env.EVENT_RETENTION_USER_DAYS,
      adminEventRetentionDays: env.EVENT_RETENTION_ADMIN_DAYS,
    },
  });

  // The delivery role (ADR-019 Decision 8, #460), in-process like the signer:
  // it fans every new event out to the destinations of the delivery routes
  // and delivers it to each at least once, retrying on the schedule the
  // EVENT_DELIVERY_* keys set. It starts on `onReady` and stops on `onClose`
  // once its attempts in flight end, so it needs the database, the signer
  // and the metrics above it, and it signs only through a `delivery` handle
  // of the signer. Its routes are the SSF route while the transmitter is on
  // and a test's own; with none it does nothing but publish its metrics. It
  // rides the default realm boot switch, as every database step at boot
  // does: a boot without a database delivers nothing. Only a process
  // that holds the `delivery` role runs it (#495).
  if (defaultRealmBoot && plugins.has('eventDelivery')) {
    await fastify.register(eventDeliveryPlugin, {
      db: fastify.db,
      signer: fastify.signer,
      routes: deliveryRoutes,
      registry: fastify.metrics.registry,
      settings: {
        maxAttempts: env.EVENT_DELIVERY_MAX_ATTEMPTS,
        retry: {
          initialDelayMs: env.EVENT_DELIVERY_RETRY_INITIAL_DELAY * 1000,
          maxDelayMs: env.EVENT_DELIVERY_RETRY_MAX_DELAY * 1000,
        },
      },
    });
  }

  // The browser session service (ADR-019 Decision 3, #469): Postgres as the
  // source of truth, Redis as a cache. It needs the database, cache and
  // metrics plugins above it and only decorates the instance; the browser
  // sign-in and the session lookup use it (#488).
  if (plugins.has('sessions')) {
    await fastify.register(sessionServicePlugin, {
      settings: {
        defaultMaxLifespanSeconds: env.SESSION_COOKIE_TTL,
        lastSeenIntervalSeconds: env.SESSION_LAST_SEEN_INTERVAL,
      },
      metrics: {
        cacheLookups: fastify.metrics.sessionCacheLookups,
        storeReads: fastify.metrics.sessionPostgresReads,
        lastSeenWrites: fastify.metrics.sessionLastSeenWrites,
      },
    });
  }

  // Global error handler (#365). This MUST precede every route registration
  // below — it used to sit after both folder autoloads (since replaced by the
  // route manifest), under a comment claiming the last position "catches all
  // unhandled errors", and that is exactly backwards. A route does not look its error handler up at request time:
  // Fastify snapshots it while closing the route's enclosing plugin
  // (`context.errorHandler = this[kErrorHandler]` in the `after()` callback of
  // `lib/route.js`). Since avvio runs queued plugins in registration order, a
  // `setErrorHandler` that runs later reaches NO route that already loaded —
  // the handler existed but was unreachable, and every error was answered by
  // Fastify's built-in `{statusCode, code, error, message}` envelope instead.
  //
  // What that silently reverted: the F-01 register-enumeration fix (PR #212),
  // which genericises `UniqueConstraintError` so the DB constraint name never
  // reaches the wire (the built-in envelope echoes `error.message`, which
  // embeds it); the RFC 6750 §3 `WWW-Authenticate: Bearer` challenge a
  // bearer-protected resource such as /oauth/userinfo MUST return on 401; the
  // RFC 6749 §5.2 OAuth error shapes; and the `error_description` sanitisation
  // that keeps that challenge header well-formed.
  //
  // It sits ahead of `cors` deliberately, not merely ahead of the routes:
  // @fastify/cors registers a route of its own — `fastify.options('*')` — so a
  // handler installed after it would leave that one route on the built-in
  // envelope. Cors answers most preflights from its `onRequest` hook before the
  // route body runs, but @fastify/rate-limit THROWS its 429 from an `onRequest`
  // hook registered earlier still, so a rate-limited OPTIONS request would
  // render the wrong shape. Registering here covers every route in this scope.
  //
  // Not covered, and never was: routes registered on the ROOT instance in
  // `main.ts` (Swagger's /docs, and the default 404 context) resolve the root's
  // error handler, not this one. Do not read this registration as "every
  // response now goes through error-handler.ts".
  await fastify.register(errorHandler);

  // CORS (F-06): fail-closed in production when CORS_ORIGIN is unset — the
  // auth-server's own browser flows (login/consent) are same-origin and do
  // not need CORS, and the JSON API is called by the same-origin developer
  // portal. Denying cross-origin by default is the safe posture; an operator
  // who needs cross-origin access sets CORS_ORIGIN explicitly. In
  // non-production the wildcard fallback is kept for local dev convenience.
  //
  // CORS_ORIGIN accepts a single origin or a comma-separated list (as the env
  // examples document). Split + trim it into an array so @fastify/cors matches
  // each origin; passing the raw comma string would be treated as one literal
  // origin and never match. Empty entries (e.g. a trailing comma) are dropped.
  const corsOrigins = env.CORS_ORIGIN
    ? env.CORS_ORIGIN.split(',')
        .map((origin) => origin.trim())
        .filter(Boolean)
    : [];
  await fastify.register(cors, {
    origin: corsOrigins.length > 0 ? corsOrigins : env.NODE_ENV === 'production' ? false : '*',
  });

  // RFC 6749 §3.2 (token endpoint) and RFC 7662 §2.1 (introspection)
  // both mandate `application/x-www-form-urlencoded` for request bodies.
  // Fastify ships with a JSON parser by default — without formbody,
  // every OAuth-spec-compliant client gets 415 Unsupported Media Type.
  // Register before routes so /oauth/* receives decoded form bodies.
  await fastify.register(formbody);

  // The routes of this process's roles (ADR-019 Decision 8, #495), from the
  // route manifest that replaced the folder autoload: each module is its own
  // encapsulated plugin, under the prefix the autoload gave it. A module the
  // manifest does not list is never registered, and every process registers
  // `/health` and `/metrics`.
  for (const { entry, plugin } of await routeModules) {
    await fastify.register(async (scope) => {
      scope.addHook('onRoute', (route) => {
        route.config = { ...route.config, serviceRoles: entry.roles };
      });
      await scope.register(plugin, entry.prefix === undefined ? {} : { prefix: entry.prefix });
    });
  }

  // Over every route of the app, a plugin's as well as a route module's: an
  // admin route registers only on the admin listener (#511), and every route
  // names its roles.
  const unplaced = registeredRoutes
    .map((route) => publicRouteProblem(route) ?? routeRolesProblem(route, roles))
    .filter((problem) => problem !== undefined);
  if (unplaced.length > 0) {
    throw new Error(unplaced.join('\n'));
  }

  // The admin API, on its own listener (ADR-019 Decisions 7 and 8, #511),
  // last: it shares the database, cache, signer, DPoP and JWT plugins above,
  // and closes before them.
  if (adminListener !== undefined) {
    if (!servesAdminListener(roles, env.ADMIN_API_ENABLED) || !plugins.has('jwt')) {
      throw new Error(
        `The admin listener runs only on a process that holds the admin role while ADMIN_API_ENABLED is on (SERVICE_ROLES=${describeServiceRoles(roles)}, ADMIN_API_ENABLED=${String(env.ADMIN_API_ENABLED)})`
      );
    }
    const { server: adminServer, ...adminOptions } = adminListener;
    await installAdminApi(adminServer, fastify, adminOptions);
  }
}
