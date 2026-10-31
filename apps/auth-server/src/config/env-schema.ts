import { BlockList, isIPv4, isIPv6 } from 'node:net';

import {
  adminApiEnvSchema,
  assuranceEnvSchema,
  authEnvSchema,
  baseEnvSchema,
  databaseEnvSchema,
  dpopEnvSchema,
  egressEnvSchema,
  emailEnvSchema,
  eventDeliveryEnvSchema,
  eventRetentionEnvSchema,
  eventTelemetryEnvSchema,
  federationEnvSchema,
  issuerKeysEnvSchema,
  keyAttestationEnvSchema,
  observabilityEnvSchema,
  otlpExporterProblems,
  passwordEnvSchema,
  PUBLISHED_SESSION_COOKIE_SECRETS,
  rateLimitEnvSchema,
  redisEnvSchema,
  serviceRolesEnvSchema,
  ssfEnvSchema,
  trustRegistryEnvSchema,
  webauthnEnvSchema,
} from '@qauth-labs/server-config';
import { z } from 'zod';

/**
 * The smallest `DB_POOL_MAX` the background jobs allow (#452). A running job
 * holds one pool connection for its advisory lock while its own queries take
 * others, so a pool of one would leave requests waiting until the lock is
 * released. The rule applies to every process, whatever its roles (#495):
 * each role but `admin` holds a job or will, and a pool of one connection
 * would starve the requests of any role.
 */
export const JOBS_MIN_DB_POOL_MAX = 2;

/** The loopback addresses: 127.0.0.0/8 and ::1. */
const LOOPBACK = new BlockList();
LOOPBACK.addSubnet('127.0.0.0', 8, 'ipv4');
LOOPBACK.addAddress('::1', 'ipv6');

/** Whether the admin listener's `host` is a loopback address, or `localhost`. */
function isLoopbackHost(host: string): boolean {
  if (host.toLowerCase() === 'localhost') return true;
  if (isIPv4(host)) return LOOPBACK.check(host, 'ipv4');
  if (isIPv6(host)) return LOOPBACK.check(host, 'ipv6');
  return false;
}

/**
 * Auth server environment schema
 * Composes all required schemas and adds app-specific configuration
 *
 * Kept apart from `env.ts`, which parses the process environment at import,
 * so a test can read the keys without booting anything. Every key here has an
 * entry in the configuration key registry (`env-schema.test.ts`).
 */
export const envSchema = z
  .object({
    ...baseEnvSchema.shape,
    // The role switch (ADR-019 Decision 8, #495): SERVICE_ROLES, default
    // `all`, and the signer service's address and internal TLS files for a
    // process without the signer. The app checks them at boot.
    ...serviceRolesEnvSchema.shape,
    // The admin API's internal listener (ADR-019 Decisions 7 and 8, #511):
    // ADMIN_API_ENABLED (default off until #517 and #520), ADMIN_API_HOST
    // (default loopback) and ADMIN_API_PORT, for a process holding `admin`.
    ...adminApiEnvSchema.shape,
    ...databaseEnvSchema.shape,
    ...redisEnvSchema.shape,
    ...passwordEnvSchema.shape,
    ...authEnvSchema.shape,
    ...rateLimitEnvSchema.shape,
    ...emailEnvSchema.shape,
    ...observabilityEnvSchema.shape,
    // The OpenTelemetry log export of events (#541): OTEL_EVENTS_ENABLED
    // (default off), OTEL_SERVICE_NAME and the standard OTEL_EXPORTER_OTLP_*
    // variables, which the exporter reads from the environment itself. They
    // are checked below, only when the export is on.
    ...eventTelemetryEnvSchema.shape,
    // The delivery role's retry schedule (#460): the attempts an event
    // delivery gets and the waits between them.
    ...eventDeliveryEnvSchema.shape,
    // Event retention (#536): the days a new realm keeps its user and admin
    // events. They seed the realm row; the realm row owns them afterwards.
    ...eventRetentionEnvSchema.shape,
    // Wallet federation (ADR-004): WALLET_FEDERATION_ENABLED (#232, default
    // off) and OID4VP_VERIFIER_PROFILE (#299, deliberately no default). Both
    // arrive through this spread, which is why federationEnvSchema must stay a
    // plain z.object — a `.superRefine()` on it would have no `.shape` here.
    ...federationEnvSchema.shape,
    // Issuer trust registry (ADR-004): OID4VP_TRUSTED_ISSUERS (#236) — the
    // per-realm allowlist of credential ISSUERS a realm accepts credentials
    // from. Separate from the two above on purpose: those configure the
    // VERIFIER direction (how QAuth proves it is the Verifier); this one is the
    // opposite direction and must never share configuration with them.
    //
    // Spread, not parsed separately, for the same reason as federation: it
    // stays a plain z.object whose per-FIELD transform turns the raw JSON into
    // a frozen, prototype-less map. Unset and blank both yield an empty map, so
    // an absent variable means "no realm trusts any issuer" rather than taking
    // the boot down — the value `${OID4VP_TRUSTED_ISSUERS:-}` in
    // docker-compose.yml expands to.
    ...trustRegistryEnvSchema.shape,
    // Assurance → `acr` (ADR-004/ADR-010, #237): OID4VP_ISSUER_ASSURANCE (which
    // issuers a realm considers assured, and at what eIDAS LoA) and
    // ACR_VALUE_STYLE (which vocabulary the emitted `acr` value is written in).
    //
    // A THIRD variable in the trust neighbourhood, kept separate from the two
    // above on purpose: OID4VP_TRUSTED_ISSUERS decides whether an issuer may be
    // accepted at all, this decides what its credentials are worth once
    // accepted. Merging them would make one of the two answers implicit.
    //
    // Spread for the same reason as the others — a plain z.object whose
    // per-FIELD transform turns raw JSON into a frozen, prototype-less map, so
    // an unset variable means "no realm assures any issuer" (hence no `acr`
    // claim anywhere) rather than taking the boot down.
    ...assuranceEnvSchema.shape,
    // Key ATTESTATION (HAIP §4.5.1, #308/#379): OID4VP_ATTESTING_ISSUERS — which
    // issuance chains validate a wallet's key attestation before issuing, and at
    // what OID4VCI Appendix D §D.2 grade.
    //
    // A FOURTH variable in the neighbourhood, and the only deployment-wide one:
    // what an issuer's issuance process establishes is a property of that
    // ecosystem, not of any realm's opinion of it. It produces EVIDENCE and never
    // a level — a realm still grants nothing unless its own OID4VP_ISSUER_ASSURANCE
    // names the issuer with `requiresKeyStorage` and its own OID4VP_TRUSTED_ISSUERS
    // accepts it, so listing an issuer here cannot raise any realm's assurance
    // on its own.
    ...keyAttestationEnvSchema.shape,
    // Issuer VERIFICATION KEYS (ADR-004): OID4VP_ISSUER_JWKS (#234/#238) — the
    // public keys credential issuers sign with, pinned in configuration. A
    // third, separate question from the two above: the profile says who WE are,
    // the allowlist says which issuers a realm ACCEPTS, and this says which key
    // an issuer SIGNS WITH. Configuring a key here grants no trust, and
    // allowlisting an issuer with no key here can never verify anything — both
    // directions fail closed, which is why they do not share a variable.
    ...issuerKeysEnvSchema.shape,
    // Passkeys (ADR-017 Decision 14, ADR-019 Decision 2, #467): WEBAUTHN_ENABLED,
    // refused when true until phase F2b is complete, the default realm's RP ID
    // with its parent-domain opt-in, and the app identifiers of the association
    // files. Spread like the others: a plain z.object with per-field rules.
    ...webauthnEnvSchema.shape,
    // DPoP (RFC 9449; ADR-014 §3, ADR-017 Decision 14, #479, #480):
    // DPOP_ENABLED, the one switch for DPoP-bound tokens.
    ...dpopEnvSchema.shape,
    // The Shared Signals Framework transmitter (ADR-018 §3, #410):
    // SSF_TRANSMITTER_ENABLED, off by default; each realm has its own switch too.
    ...ssfEnvSchema.shape,
    // The egress allowlist (ADR-019 Decision 8, #481): EGRESS_ALLOWLIST_PATH,
    // the file of non-public hosts and ranges that operator- and admin-set
    // destinations may reach, per realm. The egress plugin reads it at boot.
    // It replaces CIMD_ALLOW_PRIVATE_ADDRESSES and
    // ID_JAG_ALLOW_PRIVATE_ADDRESSES, which `readConfiguredEnv` now refuses.
    ...egressEnvSchema.shape,
    /**
     * CORS allowed origin (app-specific). When unset in `production` the
     * server denies all cross-origin requests (fail-closed); in non-production
     * it falls back to `*` for local dev convenience.
     */
    CORS_ORIGIN: z.string().optional(),
    /**
     * Expose the Swagger UI at `/docs`. Defaults to `true` outside
     * `production` and `false` in `production` so the API surface is not
     * advertised to unauthenticated callers in a hardened deployment. An
     * operator may opt back in by setting `ENABLE_SWAGGER=true` (e.g. for an
     * internal docs mirror).
     */
    ENABLE_SWAGGER: z.coerce
      .string()
      .optional()
      .transform((v) => (v === undefined ? undefined : v.toLowerCase() === 'true')),
  })
  .superRefine((env, ctx) => {
    // F-12 — reject a published SESSION_COOKIE_SECRET in production. The
    // cookies are signed with the realm's cookie key from the signer (#493),
    // so the variable is optional; but while the key boot step still reads it,
    // to import it or to replace the stored cookie key with it (until rotation
    // through the store ships, #544 and #551), a value anyone can read in
    // QAuth's examples must never reach a production key store. The boot step
    // drops those values outside production too, and every role refuses them
    // here, whether or not this process runs the boot step.
    if (
      env.NODE_ENV === 'production' &&
      env.SESSION_COOKIE_SECRET !== undefined &&
      PUBLISHED_SESSION_COOKIE_SECRETS.includes(env.SESSION_COOKIE_SECRET)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SESSION_COOKIE_SECRET'],
        message:
          "SESSION_COOKIE_SECRET is set to a value QAuth's examples published, which production refuses: anyone can sign session cookies with it. Set it to a new strong secret of at least 32 characters, for example `openssl rand -base64 48`: at boot it replaces the realm's stored cookie key, which may be that published value. Remove the variable only after that boot.",
      });
    }

    // #541 — the OTLP exporter variables are process-wide: another
    // OpenTelemetry component of the operator's may set them in a form the SDK
    // accepts and this check would not. So they are checked only when the
    // event export, which reads them, is on.
    if (env.OTEL_EVENTS_ENABLED) {
      for (const problem of otlpExporterProblems(env)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [problem.variable],
          message: problem.message,
        });
      }
    }

    // #511 — the admin listener is a second server of the same process: on
    // the public port it could not bind, and the boot would fail later with
    // an address in use.
    if (
      env.ADMIN_API_ENABLED &&
      env.SERVICE_ROLES.includes('admin') &&
      env.ADMIN_API_PORT === env.PORT
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ADMIN_API_PORT'],
        message: `ADMIN_API_PORT must differ from PORT (${env.PORT}): the admin API runs on its own listener, never on the public one.`,
      });
    }

    // #511 — until admin tokens are DPoP-bound (#520), an admin token taken in
    // transit works from anywhere that reaches the listener: in production it
    // listens on loopback only.
    if (
      env.ADMIN_API_ENABLED &&
      env.SERVICE_ROLES.includes('admin') &&
      env.NODE_ENV === 'production' &&
      !isLoopbackHost(env.ADMIN_API_HOST)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ADMIN_API_HOST'],
        message: `ADMIN_API_HOST must be a loopback address (127.0.0.0/8, ::1 or localhost) in production, not ${env.ADMIN_API_HOST}, until admin tokens are DPoP-bound (#520): a bearer admin token works from anywhere that reaches the listener.`,
      });
    }

    // #452 — the job lock takes a pool connection of its own.
    if (env.DB_POOL_MAX < JOBS_MIN_DB_POOL_MAX) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['DB_POOL_MAX'],
        message: `DB_POOL_MAX must be at least ${JOBS_MIN_DB_POOL_MAX}. A background job holds one pool connection for its lock while it runs, so with ${env.DB_POOL_MAX} requests would wait until the job ends.`,
      });
    }
  });
