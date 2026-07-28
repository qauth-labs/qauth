import { readFileSync } from 'node:fs';

import { isScriptCapableUrl } from '@qauth-labs/shared-validation';
import { z } from 'zod';

/**
 * Longest raw inline PEM bundle accepted for status-list anchors, in characters.
 *
 * Generous, because a bundle is several certificates and each is ~2 KiB of
 * base64. It is a DoS bound on a variable this process reads once, not a policy.
 */
const MAX_STATUS_LIST_ANCHOR_BUNDLE_LENGTH = 256 * 1024;

/** Longest `_PATH` value accepted. A path longer than this cannot name a file. */
const MAX_STATUS_LIST_ANCHOR_PATH_LENGTH = 4096;

/** Most status-list trust anchors one deployment may configure. */
const MAX_STATUS_LIST_ANCHORS = 32;

/** Longest raw `OID4VP_STATUS_LIST_URI_ALLOWLIST` value accepted, in characters. */
const MAX_STATUS_LIST_ALLOWLIST_LENGTH = 64 * 1024;

/**
 * Longest allowlist entry accepted, in characters.
 *
 * Mirrors the cap `server-federation`'s `createStatusListUriAllowlist` applies
 * to both a prefix and the candidate URI matched against it, so an entry here
 * can never be longer than a URI that could match it.
 */
const MAX_STATUS_LIST_URI_LENGTH = 2048;

/** Most status list URI prefixes one deployment may permit. */
const MAX_STATUS_LIST_URI_PREFIXES = 64;

/** No PEM anchors — the value of an unset anchor variable. */
const NO_ANCHOR_PEMS: readonly string[] = Object.freeze([]);

/** No permitted prefixes — the value of an unset allowlist variable. */
const NO_URI_PREFIXES: readonly string[] = Object.freeze([]);

/**
 * One PEM `CERTIFICATE` block.
 *
 * Anchors are split into individual blocks HERE rather than handed to the
 * federation layer as one bundle string, and that is load-bearing rather than
 * tidy: `new X509Certificate(bundle)` parses the FIRST certificate in a
 * multi-certificate PEM and silently ignores the rest. A three-anchor bundle
 * passed whole would anchor one issuer and quietly refuse the other two — a
 * trust decision the operator wrote and the server did not apply.
 */
const PEM_CERTIFICATE_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** Split a PEM bundle into its individual `CERTIFICATE` blocks. */
function splitCertificateBundle(bundle: string): readonly string[] {
  return bundle.match(PEM_CERTIFICATE_BLOCK) ?? [];
}

/**
 * Turn a PEM bundle into individual anchors, or report why it is not one.
 *
 * Shape only: that each block is a PARSEABLE X.509 certificate is
 * `createStatusListTrustAnchors`' answer (`server-federation`), which throws on
 * a malformed anchor rather than dropping it. Duplicating certificate parsing
 * here would put the two rule sets on a drift course, and `server-config`
 * carries no dependency on `server-federation` (config is the lowest layer).
 */
function parseCertificateBundle(
  bundle: string,
  variable: string,
  ctx: z.RefinementCtx
): readonly string[] {
  const anchors = splitCertificateBundle(bundle);

  if (anchors.length === 0) {
    ctx.addIssue({
      code: 'custom',
      message: `${variable} contains no "-----BEGIN CERTIFICATE-----" block. It must hold one or more PEM-encoded X.509 certificates`,
    });
    return z.NEVER;
  }

  if (anchors.length > MAX_STATUS_LIST_ANCHORS) {
    ctx.addIssue({
      code: 'custom',
      message: `${variable} carries ${anchors.length} certificates, more than the ${MAX_STATUS_LIST_ANCHORS} supported`,
    });
    return z.NEVER;
  }

  return Object.freeze(anchors.map((pem) => pem.trim()));
}

/** Parse the INLINE status-list anchor bundle. Unset and blank yield no anchors. */
function parseInlineStatusListAnchors(
  raw: string | undefined,
  ctx: z.RefinementCtx
): readonly string[] {
  if (raw === undefined || raw.trim() === '') return NO_ANCHOR_PEMS;
  return parseCertificateBundle(raw, 'OID4VP_STATUS_LIST_TRUST_ANCHORS', ctx);
}

/**
 * Read and parse the status-list anchor bundle NAMED BY A PATH.
 *
 * An unreadable path is a hard parse failure, exactly as `jwt.ts` treats a
 * missing `JWT_PRIVATE_KEY_PATH`: the operator stated where the anchors live, so
 * "the file is not there" is a misconfiguration and never an empty anchor set. A
 * silently empty set would make an unmounted secret look like a deployment that
 * simply configured nothing.
 */
function parseStatusListAnchorFile(
  raw: string | undefined,
  ctx: z.RefinementCtx
): readonly string[] {
  if (raw === undefined || raw.trim() === '') return NO_ANCHOR_PEMS;

  const path = raw.trim();
  let contents: string;
  try {
    contents = readFileSync(path, 'utf-8');
  } catch (error) {
    ctx.addIssue({
      code: 'custom',
      message: `OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH names a file that cannot be read (${path}): ${error instanceof Error ? error.message : String(error)}`,
    });
    return z.NEVER;
  }

  return parseCertificateBundle(contents, 'OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH', ctx);
}

/** One permitted status list URI prefix: an absolute HTTPS URL. */
const statusListUriPrefixSchema = z
  .url({
    protocol: /^https$/,
    error: 'Each OID4VP_STATUS_LIST_URI_ALLOWLIST entry must be an absolute https:// URL',
  })
  .max(MAX_STATUS_LIST_URI_LENGTH);

/**
 * Parse the comma-separated status list URI allowlist.
 *
 * Shape only, and deliberately WEAKER than what the runtime accepts:
 * `createStatusListUriAllowlist` additionally refuses userinfo, a query string,
 * a fragment, an IP literal and `localhost`, and it throws on an entry it
 * refuses rather than dropping it. Tightening those rules here as well would put
 * two rule sets on a drift course; loosening the runtime's would be a hole. What
 * this catches is the typo an operator can fix from the message alone.
 */
function parseStatusListUriAllowlist(
  raw: string | undefined,
  ctx: z.RefinementCtx
): readonly string[] {
  if (raw === undefined || raw.trim() === '') return NO_URI_PREFIXES;

  const entries = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  if (entries.length === 0) {
    ctx.addIssue({
      code: 'custom',
      message: 'OID4VP_STATUS_LIST_URI_ALLOWLIST must list at least one non-empty https:// prefix',
    });
    return z.NEVER;
  }

  if (entries.length > MAX_STATUS_LIST_URI_PREFIXES) {
    ctx.addIssue({
      code: 'custom',
      message: `OID4VP_STATUS_LIST_URI_ALLOWLIST names ${entries.length} prefixes, more than the ${MAX_STATUS_LIST_URI_PREFIXES} supported`,
    });
    return z.NEVER;
  }

  for (const [index, entry] of entries.entries()) {
    const result = statusListUriPrefixSchema.safeParse(entry);
    if (!result.success) {
      ctx.addIssue({
        code: 'custom',
        message: `OID4VP_STATUS_LIST_URI_ALLOWLIST entry ${index}: ${result.error.issues[0]?.message ?? 'is not a usable https:// prefix'}`,
      });
      return z.NEVER;
    }
  }

  return Object.freeze(entries);
}

/** The two places status-list anchors may be authored. */
export interface StatusListTrustAnchorEnvLike {
  /** Anchors written inline, as a PEM bundle. */
  readonly OID4VP_STATUS_LIST_TRUST_ANCHORS: readonly string[];
  /** Anchors read from the file `OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH` names. */
  readonly OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH: readonly string[];
}

/**
 * The full status-list anchor set this deployment configured (#297).
 *
 * The two sources are UNIONED, not one-overrides-the-other. That is a deliberate
 * deviation from `jwt.ts`'s `resolveKey`, where the `_PATH` form WINS: a signing
 * key has exactly one correct value, so two sources must be a precedence, while
 * a trust anchor set is a SET and an operator who mounts a CA bundle and adds
 * one more anchor inline means both. Neither reading can silently drop
 * configuration — union is the one that cannot.
 *
 * @param env - the parsed federation env.
 * @returns every configured anchor PEM, inline first. Empty when the deployment
 * configured none, which is the fail-closed state
 * (`NO_STATUS_LIST_TRUST_ANCHORS` refuses every Status List Token).
 */
export function resolveStatusListTrustAnchorPems(
  env: StatusListTrustAnchorEnvLike
): readonly string[] {
  return Object.freeze([
    ...env.OID4VP_STATUS_LIST_TRUST_ANCHORS,
    ...env.OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH,
  ]);
}

/**
 * Federation environment configuration (ADR-004, epic #231).
 *
 * `WALLET_FEDERATION_ENABLED` (#232) gates whether the `'wallet'`
 * `CredentialProvider` (ADR-003) is seeded into the provider registry at
 * bootstrap. It gates an INCOMPLETE epic and must stay OFF until #233–#238
 * have landed:
 *
 * - #233 OID4VP 1.0 authorization request generation + `direct_post` response
 *   intake, #234 OID4VP presentation validation,
 *   #235 VC claims normalization, #236 trust registry, #237 `acr` propagation,
 *   #238 account linking.
 * - Until then the registered provider is a skeleton whose `verify()` and
 *   `extractAttributes()` throw by design, so turning this on registers an
 *   inert entry — it cannot authenticate anyone, and it changes no existing
 *   auth flow (nothing resolves `'wallet'` yet). It exists so the flag→registry
 *   wiring is testable before the protocol work exists, not to expose a
 *   half-finished login path.
 *
 * DEFAULT OFF, like every other capability flag in this workspace
 * (cf. `HYBRID_SIGNING_ENABLED` in `crypto.ts`): an operator opts in
 * deliberately, and a deployment that never sets the variable gets the
 * behaviour it had before wallet federation existed.
 *
 * `OID4VP_VERIFIER_PROFILE` (#299) selects the `VerifierProfile` the deployment
 * operates under. It is orthogonal to the flag above: the flag decides whether
 * the wallet provider is registered at all, the profile decides what posture it
 * runs with. Both must be satisfied — an enabled deployment with no profile
 * refuses to start rather than serving wallet flows with an unstated posture.
 *
 * `OID4VP_STATUS_LIST_TRUST_ANCHORS`, its `_PATH` sibling and
 * `OID4VP_STATUS_LIST_URI_ALLOWLIST` (#297) are the two things a
 * `CredentialStatusChecker` cannot be built without — the anchors a Status List
 * Token must chain to, and the SSRF boundary on the URI a credential asks QAuth
 * to fetch. Both default to the refusing value, so an unconfigured deployment
 * wires no checker rather than a permissive one, and a profile whose
 * `requireCredentialStatus` is `true` refuses to START when either is missing
 * (`assertCredentialStatusProvisioned`).
 *
 * There is deliberately NO variable for the checker's request timeout or its
 * cache TTL. Both defaults are policy rather than tuning: 3 s is already a
 * generous outbound budget on a login path where the verified-list cache and the
 * per-origin breaker make a fetch rare, and the 300 s cache ceiling is the
 * revocation-FRESHNESS bound — it exists to stop an issuer publishing
 * `ttl: 86400` from choosing QAuth's freshness for it, so exposing it as an
 * operator knob would mostly be a way to widen the window in which an already
 * revoked credential still authenticates. `CredentialStatusCheckerConfig`
 * carries both knobs for the day a concrete deployment needs one; until then
 * every deployment gets the same, reviewed values.
 *
 * Kept a PLAIN `z.object` — no schema-level `.superRefine()`/`.transform()` —
 * so `apps/auth-server`'s env composition can spread `.shape` (a refined or
 * transformed schema has no `.shape`, which is why `cryptoEnvSchema` has to be
 * parsed separately). It is also why the two anchor sources are reconciled by
 * an exported helper ({@link resolveStatusListTrustAnchorPems}) rather than by a
 * cross-field transform: a cross-field rule would cost this schema its `.shape`.
 *
 * @see docs/adr/004-wallet-agnostic-federation.md
 */
export const federationEnvSchema = z.object({
  WALLET_FEDERATION_ENABLED: z
    .enum(['true', 'false', '1', '0'])
    .default('false')
    .transform((v) => v === 'true' || v === '1'),

  /**
   * `OID4VP_VERIFIER_PROFILE` (#299) — which `VerifierProfile` the deployment
   * operates under. See `@qauth-labs/server-federation`'s profiles module for
   * what each profile mandates.
   *
   * **OPTIONAL WITH NO DEFAULT, deliberately.** Unset means the deployment has
   * selected no profile and therefore REFUSES wallet flows. There is no
   * fallback: `haip-1.0` is not a stricter `oid4vp-1.0-base`, it is a different
   * ecosystem demanding a QTSP-issued WRPAC, so neither is a safe default for a
   * deployment that did not ask for it. #296 (LOCKED 2026-07-20): *"There is
   * never a permissive fallback to the more capable profile."*
   *
   * This differs from `WALLET_FEDERATION_ENABLED` above, which defaults to a
   * value (`false`). A flag has a safe off-state; a profile choice does not have
   * a safe default at all, only an absence.
   *
   * `z.enum` rather than a free string: an unrecognised value is rejected at
   * parse time, so a typo fails the boot rather than silently selecting nothing
   * and looking like a deliberate opt-out.
   *
   * **Empty and whitespace-only are treated as UNSET, not as a bad value.**
   * `parseEnv` validates the whole composed auth-server env in one `.parse()` at
   * module import, so a `ZodError` on this field takes the process down before
   * it listens — password login, `/authorize` and `/token` included — for a
   * deployment that may have no interest in wallet federation at all. And an
   * empty string is what an *absent* variable looks like once a shell or
   * orchestrator materialises it: this repo's own `docker-compose.yml` uses the
   * `${VAR:-}` form (cf. `REDIS_PASSWORD`, `JWT_PUBLIC_KEY`, `CORS_ORIGIN`), and
   * the workspace's other optional strings (`RESEND_API_KEY` in `email.ts`)
   * already tolerate it. Blanking a variable is how operators express "not
   * configured", so it must land on the same branch as omitting it.
   *
   * This does NOT soften the guard. Empty means no profile selected, which is
   * exactly the state that makes an enabled deployment refuse to serve wallet
   * flows (#296 LOCKED — no permissive fallback). A typo (`haip`, `HAIP-1.0`)
   * is still a hard parse failure; only "operator said nothing" is forgiven.
   *
   * `z.preprocess` is applied per FIELD, never to the schema object, so
   * `federationEnvSchema` stays a plain `z.object` with a usable `.shape`.
   *
   * Values are duplicated from `VerifierProfileId` rather than imported —
   * `server-config` deliberately carries no dependency on `server-federation`
   * (config is the lowest layer, and inverting that would make every consumer of
   * a database URL pull in OID4VP). The duplication is pinned to
   * `VERIFIER_PROFILE_IDS` by `apps/auth-server`'s env test
   * (`src/config/env.test.ts`) — the lowest layer permitted to import both libs,
   * and therefore the only place the two lists can be compared. Neither this
   * file's test nor `verifier-profiles.test.ts` can see the other list, so
   * neither of them fails when a profile is added; that auth-server test does.
   */
  OID4VP_VERIFIER_PROFILE: z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z.enum(['oid4vp-1.0-base', 'haip-1.0']).optional()
  ),

  /**
   * `OID4VP_REQUESTED_VCT` (#239) — the Verifiable Credential Types the wallet
   * login flow asks for, as a comma-separated list of `vct` values.
   *
   * **OPTIONAL WITH NO DEFAULT, and the wallet-login UI is not offered without
   * it.** There is no safe default: a DCQL query carrying no type constraint
   * asks a wallet for "any credential you hold", which OID4VP 1.0 §15.6 warns
   * Verifiers against and which leaves the trust registry (#236) nothing to
   * decide on. Inventing a plausible-looking default (`urn:eudi:pid:1`, say)
   * would be worse than none: a deployment would silently request a credential
   * its operator never chose to accept.
   *
   * Same empty-is-unset handling as `OID4VP_VERIFIER_PROFILE` above, for the
   * same reason — `${VAR:-}` is how an orchestrator materialises an absent
   * variable, and blanking one is how an operator says "not configured".
   *
   * A `vct` is an arbitrary string (SD-JWT VC draft-13 §3.2.2.2), so the shape
   * check here is deliberately weak: non-empty entries with no whitespace. What
   * makes a value ACCEPTABLE is the issuer trust decision, not its syntax.
   */
  OID4VP_REQUESTED_VCT: z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z
      .string()
      .max(2048)
      .transform((value) =>
        Object.freeze(
          value
            .split(',')
            .map((entry) => entry.trim())
            .filter((entry) => entry.length > 0)
        )
      )
      .refine((values) => values.length > 0, {
        message: 'OID4VP_REQUESTED_VCT must list at least one non-empty vct value',
      })
      .refine((values) => values.every((entry) => !/\s/.test(entry)), {
        message: 'OID4VP_REQUESTED_VCT entries must not contain whitespace',
      })
      .optional()
  ),

  /**
   * `OID4VP_SUBJECT_RESOLUTION` (#300) — which `SubjectResolutionStrategy`
   * decides WHICH ACCOUNT a validated presentation belongs to.
   *
   * ADR-009 Finding 1: there is no protocol-guaranteed stable wallet subject
   * identifier, and the ecosystem is deliberately built to keep it that way. So
   * account resolution is a deployment decision rather than a protocol
   * consequence, and this is where a deployment states it.
   *
   * **OPTIONAL WITH NO DEFAULT here**, but — unlike
   * `OID4VP_VERIFIER_PROFILE` — absence is not a refusal: the active
   * `VerifierProfile` supplies the default (`asserted-lookup` for both shipped
   * profiles, ADR-009 §1). Leaving this unset therefore means "whatever the
   * profile says", which is a real answer; a *typo* is still a hard parse
   * failure. Same empty-is-unset handling as the variables above, for the same
   * `${VAR:-}` reason.
   *
   * The enum lists **every** strategy ADR-009 names, including the ones that are
   * reserved rather than implemented (`key-thumbprint`, `rp-pseudonym`) and the
   * one that is not a login strategy (`session-binding`). That is deliberate: a
   * value this schema rejects produces a `ZodError` naming a list of strings,
   * while a value it accepts and the federation gate then refuses produces
   * `assertSubjectResolutionStrategySelectable`'s explanation of the actual gate
   * — the WebAuthn workstream, the missing technical specification, the rotating
   * key material. The operator needs the second message, not the first.
   *
   * Values are duplicated from `SubjectResolutionStrategyId` rather than
   * imported, for the same layering reason as `OID4VP_VERIFIER_PROFILE` above,
   * and pinned to `SUBJECT_RESOLUTION_STRATEGY_IDS` by `apps/auth-server`'s
   * `src/config/env.test.ts`.
   */
  OID4VP_SUBJECT_RESOLUTION: z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z
      .enum([
        'asserted-lookup',
        'issuer-scoped-claim',
        'session-binding',
        'key-thumbprint',
        'rp-pseudonym',
      ])
      .optional()
  ),

  /**
   * `OID4VP_SUBJECT_BINDING_CLAIMS` (#300) — the credential claims the wallet
   * binding is derived from, as a comma-separated list of claim names.
   *
   * This is the ENTITLEMENT CHECK of `asserted-lookup`, and ADR-009 §1 restates
   * why it is load-bearing *"because it is the likeliest way this gets built
   * wrong"*: a validated, issuer-trusted presentation proves only that the
   * holder has *a* valid credential. Without a binding to match, any valid
   * credential would authenticate any account.
   *
   * **No default, and an unset value is not a soft failure.** The claim set is
   * ecosystem-specific — an EUDI PID deployment binds on the mandatory attribute
   * set, a workforce deployment on an employee number — and a plausible-looking
   * default would silently be a weak binding nobody reviewed. A deployment that
   * selects (or inherits) `asserted-lookup` and sets nothing here fails at the
   * federation gate rather than serving an unchecked login.
   *
   * Shape only: claim names are non-empty and whitespace-free. WHICH claims
   * constitute an identity is the operator's ecosystem knowledge, not this
   * layer's — with one exception enforced downstream, that `iss` and `cnf` may
   * never be named (ADR-009 §2 and OID4VP 1.0 §15.5–§15.6).
   */
  OID4VP_SUBJECT_BINDING_CLAIMS: z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z
      .string()
      .max(2048)
      .transform((value) =>
        Object.freeze(
          value
            .split(',')
            .map((entry) => entry.trim())
            .filter((entry) => entry.length > 0)
        )
      )
      .refine((values) => values.length > 0, {
        message: 'OID4VP_SUBJECT_BINDING_CLAIMS must list at least one non-empty claim name',
      })
      .refine((values) => values.every((entry) => !/\s/.test(entry)), {
        message: 'OID4VP_SUBJECT_BINDING_CLAIMS entries must not contain whitespace',
      })
      .optional()
  ),

  /**
   * `OID4VP_SUBJECT_CLAIM` (#300) — the claim carrying the issuer's stable
   * subject identifier, for `issuer-scoped-claim` only (ADR-009 §2).
   *
   * Ignored by every other strategy. Required when
   * `OID4VP_SUBJECT_RESOLUTION=issuer-scoped-claim`, which the federation gate
   * enforces rather than this schema — the requirement is conditional on another
   * variable, and expressing it here would need a `.superRefine()` that costs
   * `federationEnvSchema` its `.shape` (see the module JSDoc).
   */
  OID4VP_SUBJECT_CLAIM: z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z
      .string()
      .max(256)
      .refine((value) => !/\s/.test(value), {
        message: 'OID4VP_SUBJECT_CLAIM must not contain whitespace',
      })
      .optional()
  ),

  /**
   * `OID4VP_SUBJECT_CLAIM_ISSUERS` (#300) — the issuers `issuer-scoped-claim` is
   * opted into, as a comma-separated list of `https://` issuer identifiers.
   *
   * ADR-009 §2 permits the strategy only *"where a specific, named issuer
   * contractually guarantees a stable, disclosed claim"* — a guarantee QAuth
   * cannot verify in code. So the operator names the issuers it holds that
   * guarantee from, and a presentation from any other trusted issuer takes the
   * mandatory `asserted-lookup` fallback instead.
   *
   * Distinct from `OID4VP_TRUSTED_ISSUERS` (#236) and never a substitute for it:
   * that list decides whether a credential counts at all, this one decides
   * whether one of those credentials may KEY an account. An issuer here that is
   * not also trusted there is inert.
   *
   * Shape only. Entries are canonicalized and validated by
   * `server-federation`'s `normalizeIssuerScopedIssuers`, which is the same
   * reduction `ValidatedIssuer` applies to the identity being matched.
   */
  OID4VP_SUBJECT_CLAIM_ISSUERS: z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z
      .string()
      .max(4096)
      .transform((value) =>
        Object.freeze(
          value
            .split(',')
            .map((entry) => entry.trim())
            .filter((entry) => entry.length > 0)
        )
      )
      .refine((values) => values.length > 0, {
        message: 'OID4VP_SUBJECT_CLAIM_ISSUERS must list at least one non-empty issuer identifier',
      })
      .optional()
  ),

  /**
   * `OID4VP_WALLET_INVOCATION_ENDPOINT` (#239) — the wallet Authorization
   * Endpoint the QR code and deep-link button target.
   *
   * OID4VP 1.0 §5 delivers the request as query parameters of the wallet's own
   * Authorization Endpoint, which is either a custom scheme (`openid4vp://`) or
   * a universal link belonging to a specific wallet. The default is the
   * registered custom scheme, because that is the value that reaches whichever
   * wallet the user actually has installed; a deployment targeting one wallet
   * vendor overrides it with that vendor's universal link.
   *
   * Validated for SHAPE — an absolute URI reference with a scheme, no
   * whitespace and no fragment (a fragment would be dropped before the wallet
   * ever saw the parameters). WHICH endpoint is correct is an ecosystem question
   * this layer cannot answer.
   *
   * ...with ONE semantic exception: the scheme must not be script-capable. This
   * value is rendered into an `href` on the wallet-login screen, so
   * `javascript:alert(1)` here is a stored XSS payload served to every user who
   * reaches that page — and it satisfies the shape regex above perfectly, being a
   * well-formed absolute URI. "Operator-supplied" is not "trusted": a leaked CI
   * variable, a mis-merged Helm value or a compromised secret store all write
   * this string, and the boot is where that must fail.
   *
   * A scheme ALLOWLIST is impossible here — wallet schemes are open-ended
   * (`openid4vp://`, `haip://`, `eudi-wallet://`, a vendor's own) and no registry
   * enumerates them. It is also unnecessary: the schemes that EXECUTE are a small
   * closed set, so `isScriptCapableUrl` refuses those instead, matching them the
   * way a browser resolves a scheme rather than the way the string reads (see
   * `@qauth-labs/shared-validation`'s url module). The render path applies the
   * same check again via `html.ts#safeCustomSchemeUrl()`, so neither end is
   * load-bearing alone.
   */
  OID4VP_WALLET_INVOCATION_ENDPOINT: z
    .string()
    .max(512)
    .regex(
      /^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s#]*$/,
      'OID4VP_WALLET_INVOCATION_ENDPOINT must be an absolute URI with a scheme and no fragment'
    )
    .refine((value) => !isScriptCapableUrl(value), {
      message:
        'OID4VP_WALLET_INVOCATION_ENDPOINT must not use a script-capable scheme ' +
        '(javascript:, data:, vbscript: and friends) — it is rendered as a link',
    })
    .default('openid4vp://'),

  /**
   * `OID4VP_STATUS_LIST_TRUST_ANCHORS` (#297) — the X.509 anchors a Status List
   * Token's `x5c` chain must terminate at, as an inline PEM bundle.
   *
   * ## A FOURTH trust question, and it shares configuration with none of the
   * other three
   *
   * | variable | question |
   * | --- | --- |
   * | `OID4VP_VERIFIER_PROFILE` | who are WE, to a wallet? |
   * | `OID4VP_TRUSTED_ISSUERS` | which CREDENTIAL issuers does a realm accept? |
   * | `OID4VP_ISSUER_JWKS` | which key does a credential issuer sign with? |
   * | this | which CA may vouch for a STATUS issuer? |
   *
   * The Status List Token is signed by the status issuer, which need not be the
   * credential issuer, and is fetched over a URI the CREDENTIAL supplied.
   * Nothing about the presentation authenticates it. Without anchors the feature
   * inverts into a vulnerability: a verifier that fetches a document from an
   * attacker-named URI and believes what it says has not added revocation
   * checking, it has added a way to assert that a revoked credential is valid
   * (HAIP §6.1.1 — `x5c`, trust anchor excluded, leaf not self-signed).
   *
   * ## Fail-closed
   *
   * Unset and blank both mean "this deployment anchors no status issuer", which
   * `createStatusListTrustAnchors` turns into `NO_STATUS_LIST_TRUST_ANCHORS` —
   * an anchor set that refuses every token. Anything PRESENT but malformed is a
   * hard parse failure, for the same reason `OID4VP_TRUSTED_ISSUERS` is: a typo
   * must not degrade silently into the legitimate default, because the operator
   * would have no way to tell the two apart.
   *
   * ## Shape
   *
   * One or more concatenated PEM `CERTIFICATE` blocks, exactly as `cat`ting
   * several `.crt` files produces. Real newlines, quoted, as `JWT_PRIVATE_KEY`
   * is authored in `.env.example`; there is no `\n`-escape handling, here or
   * anywhere else in this workspace. Prefer
   * {@link OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH} for anything beyond one
   * certificate — a CA bundle is what an orchestrator mounts as a file.
   */
  OID4VP_STATUS_LIST_TRUST_ANCHORS: z
    .string()
    .max(
      MAX_STATUS_LIST_ANCHOR_BUNDLE_LENGTH,
      `OID4VP_STATUS_LIST_TRUST_ANCHORS must be at most ${MAX_STATUS_LIST_ANCHOR_BUNDLE_LENGTH} characters — a bundle that large is a configuration mistake`
    )
    .optional()
    .transform(parseInlineStatusListAnchors),

  /**
   * `OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH` (#297) — a file holding the same PEM
   * bundle.
   *
   * The `_PATH` sibling every PEM-carrying variable in this workspace has
   * (`JWT_PRIVATE_KEY_PATH`, `JWT_RS256_PRIVATE_KEY_PATH`,
   * `JWT_MLDSA_PRIVATE_KEY_PATH`), and the form to reach for here: a CA bundle
   * is several kilobytes of multi-line base64, which is exactly what a mounted
   * secret or ConfigMap is for and exactly what an environment variable is bad
   * at.
   *
   * UNIONED with the inline variable rather than overriding it — see
   * {@link resolveStatusListTrustAnchorPems} for why this one case departs from
   * `jwt.ts`'s path-wins precedence.
   *
   * A path that is SET but unreadable fails the boot. Unset and blank are
   * "no anchors from a file", which is not an error on its own.
   */
  OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH: z
    .string()
    .max(MAX_STATUS_LIST_ANCHOR_PATH_LENGTH)
    .optional()
    .transform(parseStatusListAnchorFile),

  /**
   * `OID4VP_STATUS_LIST_URI_ALLOWLIST` (#297) — where status lists may be
   * fetched from, as a comma-separated list of `https://` URI prefixes.
   *
   * ## This is an SSRF boundary, not a convenience
   *
   * Every other input on the wallet path is data QAuth parses. A status list URI
   * is different in kind: it is a string the CREDENTIAL chose that QAuth is
   * asked to make an outbound request to, and a credential is trivially minted
   * with `status.status_list.uri = "https://169.254.169.254/…"`. There is no
   * ordering that makes an unconstrained fetch safe — signature verification
   * needs the fetched document — so the URI is constrained before it is dialled.
   *
   * An allowlist rather than a blocklist because the legitimate set is small and
   * known: a deployment federates with a handful of issuers whose status
   * endpoints its operator can name. A blocklist of "internal" addresses is a
   * losing game (DNS names resolving into RFC 1918, IPv6-mapped IPv4, redirects,
   * rebinding).
   *
   * ## Matching
   *
   * ORIGIN plus a SEGMENT-anchored path prefix, applied by
   * `createStatusListUriAllowlist`, never a `startsWith`. A prefix with no path
   * pins the whole origin, which is the common configuration. Entries must carry
   * no query string, no fragment and no userinfo, and the runtime refuses IP
   * literals and `localhost` whatever this variable says.
   *
   * ## Fail-closed
   *
   * Unset and blank both mean "status lists may be fetched from nowhere", which
   * `DENY_ALL_STATUS_LIST_URI_ALLOWLIST` enforces by refusing every URI. That is
   * the right default: a deployment that has not named its issuers' status
   * endpoints has not decided where QAuth may make outbound requests.
   *
   * ```
   * OID4VP_STATUS_LIST_URI_ALLOWLIST=https://issuer.example/statuslists,https://status.other.example
   * ```
   */
  OID4VP_STATUS_LIST_URI_ALLOWLIST: z
    .string()
    .max(
      MAX_STATUS_LIST_ALLOWLIST_LENGTH,
      `OID4VP_STATUS_LIST_URI_ALLOWLIST must be at most ${MAX_STATUS_LIST_ALLOWLIST_LENGTH} characters — an allowlist that large is a configuration mistake`
    )
    .optional()
    .transform(parseStatusListUriAllowlist),
});

/** Federation environment configuration type. */
export type FederationEnv = z.infer<typeof federationEnvSchema>;
