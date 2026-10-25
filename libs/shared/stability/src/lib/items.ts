import type { ConditionEvidence, ExperimentalItem } from './item';

/**
 * The experimental-feature registry: every experimental item of ADR-018 §4,
 * once. An item is added here in the same pull request that adds its switch,
 * and an item listed before it is built says `built: false`.
 */

/** A condition that does not hold yet. */
const open = (note?: string): ConditionEvidence =>
  note === undefined ? { evidence: [] } : { evidence: [], note };

const FIPA_SPEC = {
  name: 'OAuth 2.0 for First-Party Applications',
  url: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/',
  status: 'draft',
} as const;

const AUDIT_PENDING = open('The external audit of ADR-018 §8 has not taken place.');
const NO_BETA = open('No beta has run outside the project.');

export const EXPERIMENTAL_ITEMS = [
  {
    id: 'fipa-challenge-endpoint',
    title: 'The FiPA authorization challenge endpoint',
    description:
      'Headless sign-in for first-party native apps at `POST /oauth/authorize-challenge`. It stays experimental until FiPA is an RFC; the engine behind it is stable, because the hosted pages use it. PKCE is on by default there, and a per-client setting can switch it off: the single exception to mandatory PKCE.',
    adr: 'docs/adr/017-first-party-login.md',
    surface: 'server',
    switchKey: 'FIRST_PARTY_LOGIN_ENABLED',
    switchValue: 'true',
    requires: [],
    // FiPA §8 "Authorization Server Metadata"; ADR-017 §11.
    discoveryMembers: ['authorization_challenge_endpoint'],
    docsPage: null,
    spec: FIPA_SPEC,
    built: false,
    stable: false,
    conditions: {
      'spec-final': open('FiPA is an Internet-Draft.'),
      'external-beta': NO_BETA,
      'external-audit': AUDIT_PENDING,
      'conformance-tests': open(),
    },
  },
  {
    id: 'node-first-party',
    title: 'The `/first-party` subpath of `@qauth-labs/node`',
    description:
      'The Node.js SDK entry point that talks to the FiPA authorization challenge endpoint. It stays experimental with the endpoint, until FiPA is an RFC.',
    adr: 'docs/adr/017-first-party-login.md',
    surface: 'sdk',
    switchKey: '@qauth-labs/node/first-party',
    switchValue: null,
    requires: [],
    discoveryMembers: [],
    docsPage: null,
    spec: FIPA_SPEC,
    built: false,
    stable: false,
    conditions: {
      'spec-final': open('FiPA is an Internet-Draft.'),
      'external-beta': NO_BETA,
      'external-audit': AUDIT_PENDING,
      'conformance-tests': open(),
    },
  },
  {
    id: 'oid4vp-1.0-base',
    title: 'The `oid4vp-1.0-base` verifier profile',
    description:
      'The OpenID for Verifiable Presentations 1.0 profile for wallet sign-in. It stays supported, but it allows looser options than HAIP 1.0, such as unsigned requests, so it stays outside the stability promise; `haip-1.0` is the stable profile.',
    adr: 'docs/adr/018-1-0-scope-and-stability.md',
    surface: 'server',
    switchKey: 'OID4VP_VERIFIER_PROFILE',
    switchValue: 'oid4vp-1.0-base',
    requires: ['WALLET_FEDERATION_ENABLED=true'],
    // The profile changes how a wallet presentation is requested and checked;
    // no discovery member describes it.
    discoveryMembers: [],
    docsPage: '/integrate/wallet-login/',
    spec: {
      name: 'OpenID for Verifiable Presentations 1.0',
      url: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html',
      status: 'final',
    },
    built: true,
    stable: false,
    conditions: {
      'spec-final': {
        evidence: ['https://openid.net/specs/openid-4-verifiable-presentations-1_0.html'],
        note: 'OpenID4VP 1.0 is an OpenID Foundation Final Specification.',
      },
      'external-beta': open(
        'No beta has run outside the project; the profile is validated against a mock wallet.'
      ),
      'external-audit': AUDIT_PENDING,
      'conformance-tests': open(
        'The conformance matrix maps part of OpenID4VP 1.0 (`docs/conformance/requirements/oid4vp-1_0.json`); it does not cover the profile as a whole.'
      ),
    },
  },
  {
    id: 'attestation-client-auth',
    title: 'Attestation-based client authentication',
    description:
      'Native apps authenticate to the token endpoint with a client attestation, phase F4 of ADR-017. It stays experimental unless the attestation draft is an RFC before 1.0 is cut.',
    adr: 'docs/adr/017-first-party-login.md',
    surface: 'server',
    switchKey: null,
    switchValue: null,
    requires: [],
    // The attestation draft's §8 "Authorization Server and Resource Server
    // Metadata"; ADR-017 §11. Its `attest_jwt_client_auth_dpop` method is a
    // value of the stable `token_endpoint_auth_methods_supported`, not a member.
    discoveryMembers: [
      'client_attestation_signing_alg_values_supported',
      'client_attestation_pop_signing_alg_values_supported',
    ],
    docsPage: null,
    spec: {
      name: 'OAuth 2.0 Attestation-Based Client Authentication',
      url: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/',
      status: 'draft',
    },
    built: false,
    stable: false,
    conditions: {
      'spec-final': open('The attestation draft is an Internet-Draft.'),
      'external-beta': NO_BETA,
      'external-audit': AUDIT_PENDING,
      'conformance-tests': open(),
    },
  },
  {
    id: 'pass-through-leg',
    title: 'The pass-through leg of the Authority Tree',
    description:
      "Work on a platform that cannot issue a narrowed credential stays inside the tree: the broker vends the owner's own token. It is temporary and weaker by design, with no narrowing. The rest of the Authority Tree is stable.",
    adr: 'docs/adr/016-agent-platform-bindings.md',
    surface: 'server',
    switchKey: 'PASS_THROUGH_LEG_ENABLED',
    switchValue: 'true',
    requires: ['AUTHORITY_TREE_ENABLED=true'],
    discoveryMembers: [],
    docsPage: null,
    spec: {
      name: 'The pass-through leg, ADR-016 §4',
      url: 'https://docs.qauth.dev/reference/records/adr/016-agent-platform-bindings/',
      status: 'draft',
    },
    built: false,
    stable: false,
    conditions: {
      'spec-final': open('QAuth defines the leg itself, in ADR-016 §4.'),
      'external-beta': NO_BETA,
      'external-audit': AUDIT_PENDING,
      'conformance-tests': open(),
    },
  },
  {
    id: 'plugin-api',
    title: 'The plugin API',
    description:
      "The AuthMethod contract as plugins see it. It is public and documented, so others can write plugins, but it may change in a minor release. It becomes stable in 1.x, after QAuth's own plugins have matured on it; those first-party plugins are part of 1.0.",
    adr: 'docs/adr/018-1-0-scope-and-stability.md',
    surface: 'server',
    switchKey: null,
    switchValue: null,
    requires: [],
    discoveryMembers: [],
    docsPage: null,
    spec: {
      name: 'The AuthMethod contract, ADR-018',
      url: 'https://docs.qauth.dev/reference/records/adr/018-1-0-scope-and-stability/',
      status: 'draft',
    },
    built: false,
    stable: false,
    conditions: {
      'spec-final': open('QAuth defines the contract itself; ADR-018 §4 makes it stable in 1.x.'),
      'external-beta': NO_BETA,
      'external-audit': AUDIT_PENDING,
      'conformance-tests': open(),
    },
  },
] as const satisfies readonly ExperimentalItem[];

/** The id of every registered item, as a union. */
export type ExperimentalItemId = (typeof EXPERIMENTAL_ITEMS)[number]['id'];

/** The id of every built item of the auth server: each needs a switch the server reads. */
export type BuiltServerItemId = Extract<
  (typeof EXPERIMENTAL_ITEMS)[number],
  { readonly built: true; readonly surface: 'server' }
>['id'];
