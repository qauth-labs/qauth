/**
 * The typed client of the QAuth Interaction API v1-rc.0, generated from
 * `apps/docs-site/public/interaction/v1-rc.0/openapi.json` by
 * `pnpm exec nx run shared-interaction-client:generate`. Do not edit it by
 * hand: the tests fail while it differs from what the generator writes.
 */

import { type CallInit, callOperation, type InteractionClientOptions } from '../lib/runtime';

/** The version label of the document this client was generated from. */
export const INTERACTION_API_VERSION = 'v1-rc.0';

/** The opaque interaction id: 32 random bytes the authorization endpoint created (#592). The server stores only its hash. Any other value gets the same `interaction_expired` as an unknown id. */
export type InteractionId = string;

/** The CSRF value of the step read it came with: valid for one answer to that step view, bound to the interaction, and never put in a URL. The ceremony app embeds it; it cannot mint one. */
export type Csrf = string;

/** An interaction as its current step shows it: the step, the alternatives, the CSRF value for one answer, who the client is and the realm’s brand. No personal data. */
export interface Interaction {
  step: Step;
  /** The other steps the engine accepts as the next answer, preferred first: "try another way" and the paths a page links to (a reset, a resend). Never the current step, and never with `error`. */
  alternatives: Step[];
  csrf: Csrf;
  client?: ClientDisplay;
  brand: Brand;
  /** The `ui_locales` of the authorization request, validated, in order. */
  uiLocales?: string[];
  /** When the interaction expires. */
  expiresAt: string;
}

/** One step, by its name. */
export type Step =
  | IdentifierStep
  | PasswordStep
  | EmailCodeStep
  | NewPasswordStep
  | PasswordResetStep
  | CaptchaStep
  | WebauthnGetStep
  | WebauthnCreateStep
  | TotpStep
  | RecoveryCodeStep
  | RecoveryCodesStep
  | TotpSetupStep
  | ConsentStep
  | SelectAccountStep
  | DeviceCodeStep
  | DeviceConfirmStep
  | LogoutConfirmStep;

/** An answer to one step, by its name: the envelope’s `type` and `csrf`, and the step’s answer fields. */
export type AnswerRequest =
  | IdentifierAnswer
  | PasswordAnswer
  | EmailCodeAnswer
  | NewPasswordAnswer
  | PasswordResetAnswer
  | CaptchaAnswer
  | WebauthnGetAnswer
  | WebauthnCreateAnswer
  | TotpAnswer
  | RecoveryCodeAnswer
  | RecoveryCodesAnswer
  | TotpSetupAnswer
  | ConsentAnswer
  | SelectAccountAnswer
  | DeviceCodeAnswer
  | DeviceConfirmAnswer
  | LogoutConfirmAnswer;

/** What a JSON answer leads to. A form post gets the same as a `303 See Other` instead (#616). */
export type AnswerResult = NextStepResult | RedirectResult;

/** The next step: the same as a step read now returns. A refused answer gets the same step back, with its `error` set and a new CSRF value. */
export interface NextStepResult {
  /** Another step comes next, or the same one again. */
  result: 'step';
  interaction: Interaction;
}

/** The final redirect. The page navigates to `location`. */
export interface RedirectResult {
  /** The interaction is finished. */
  result: 'redirect';
  /** Where the browser goes now: the authorization response to the client, the post-logout redirect, or a page of the ceremony app when no client waits, as at the end of a device authorization. Taken from the interaction record and the realm, never from the request. */
  location: string;
}

/** Cancel the interaction. The client gets `access_denied` with its `state` and `iss`; a logout ends with the person still signed in. */
export interface CancelRequest {
  csrf: Csrf;
}

/** The personal data of the current step, by its name. */
export type PersonalData =
  | IdentifierPersonal
  | PasswordPersonal
  | EmailCodePersonal
  | NewPasswordPersonal
  | PasswordResetPersonal
  | CaptchaPersonal
  | WebauthnGetPersonal
  | WebauthnCreatePersonal
  | TotpPersonal
  | RecoveryCodePersonal
  | RecoveryCodesPersonal
  | TotpSetupPersonal
  | ConsentPersonal
  | SelectAccountPersonal
  | DeviceCodePersonal
  | DeviceConfirmPersonal
  | LogoutConfirmPersonal;

/** Who the client is, as the auth server’s own records say (#593). Client-supplied text is untrusted: no logo comes from a client-supplied URL, and an unverified client shows none. */
export interface ClientDisplay {
  /** How the client is known, which decides what is verified (ADR-019 Decision 6): a Client ID Metadata Document client (the host of its client id URL), a client an admin registered (the domain the admin set), a federation client (its entity id and trust marks), or a dynamically registered or developer-portal client (nothing: the screen says the app is unverified). */
  kind: 'cimd' | 'admin_registered' | 'federation' | 'unverified';
  /** For `cimd` and `admin_registered`: the verified domain, which the screen shows first. */
  verifiedDomain?: {
    /** The verified host, in ASCII (punycode) form. */
    host: string;
    /** The part of `host` the screen highlights: its registrable domain. */
    registrableDomain: string;
    /** Whether `host` sits under a shared-hosting suffix, from the private section of the Public Suffix List: the screen flags it. */
    sharedHosting: boolean;
  };
  /** For `federation`: the entity id and its validated trust marks. */
  federation?: {
    /** The federation entity id. */
    entityId: string;
    /** The trust marks the server validated. */
    trustMarks: Array<{
      /** The trust mark type. */
      id: string;
      /** The trust mark issuer’s entity id. */
      issuer: string;
    }>;
  };
  /** Where the code goes, from the redirect URI the request was bound to. Absent when no code goes anywhere, as on a logout. */
  redirect?: {
    /** Where the authorization code goes: a web host, a loopback address (shown as "this device", with a warning), or a native app’s own URI scheme. */
    target: 'host' | 'this_device' | 'app';
    /** For `host`: the host that receives the code. */
    host?: string;
    /** For `app`: the URI scheme of the app. */
    scheme?: string;
  };
  /** The name the client declared about itself: length-capped and stripped. The screen marks it as declared and never shows it above or instead of the verified data. */
  declaredName?: string;
  logo?: Asset;
  /** Whether the client registered itself recently: the screen shows a badge. */
  newClient: boolean;
}

/** The realm’s brand settings, the theme tier of ADR-019 Decision 5: a logo, colours, a font from a safe list, links, per-locale strings and dark mode. No uploaded templates, CSS or script. Admins set them in the admin console; a realm that set nothing gets the defaults, and every member left out keeps the ceremony app’s own. */
export interface Brand {
  /** The realm’s logo, for light and, optionally, dark mode. Absent when no admin uploaded one: the page shows the service’s name. */
  logo?: {
    light: Asset;
    dark?: Asset;
  };
  /** The brand colours. The ceremony app derives text colours from them and keeps WCAG 2.2 AA contrast. */
  colors?: {
    /** Colours for one colour scheme. A colour left out keeps the ceremony app’s default. */
    light?: {
      /** The brand colour of buttons and links. */
      primary?: string;
      /** The page background. */
      background?: string;
    };
    /** Colours for one colour scheme. A colour left out keeps the ceremony app’s default. */
    dark?: {
      /** The brand colour of buttons and links. */
      primary?: string;
      /** The page background. */
      background?: string;
    };
  };
  /** A font from the safe list the ceremony app serves from the realm origin. `system` loads none and uses the platform’s interface font. A page that does not know a value uses `system`. */
  font:
    | 'system'
    | 'inter'
    | 'noto_sans'
    | 'atkinson_hyperlegible'
    | 'ibm_plex_sans'
    | 'source_sans_3'
    | (string & {});
  /** Links the pages show in their footer, when set. */
  links?: {
    /** The terms of service. */
    terms?: string;
    /** The privacy notice. */
    privacy?: string;
    /** Where to get help. */
    help?: string;
  };
  /** The realm’s strings, by locale. The page picks the first of the interaction’s `uiLocales` it has strings for, then its own default. */
  strings?: {
    [key: string]: BrandStrings;
  };
  /** `enabled`: the pages follow the system setting and offer a switch. `disabled`: the realm turned dark mode off on its sign-in pages (ADR-020 §5). */
  darkMode: 'enabled' | 'disabled';
}

/** The realm’s own strings for one locale. A string left out keeps the ceremony app’s text. */
export interface BrandStrings {
  /** The service’s display name, in headings and as the logo’s text alternative. */
  name?: string;
  /** The sign-in page heading. */
  title?: string;
  /** A short notice at the foot of every page. */
  footer?: string;
}

/** An image an admin uploaded, re-encoded by the server and served from the realm origin. Never a URL a client supplied (ADR-019 Decision 6). */
export interface Asset {
  /** Where the realm origin serves the image. */
  url: string;
  /** Its width in pixels. */
  width: number;
  /** Its height in pixels. */
  height: number;
}

/** An RFC 9457 problem details document with a stable `code` and a `trace_id`, and no prose: no `detail`, no `instance`, no `errors`. */
export interface Problem {
  /** RFC 9457 §4.2.1: no type beyond the HTTP status. Branch on `code`. */
  type: 'about:blank';
  /** The HTTP status phrase. Not for branching, and not for a screen. */
  title:
    | 'Bad Request'
    | 'Forbidden'
    | 'Gone'
    | 'Content Too Large'
    | 'Unsupported Media Type'
    | 'Misdirected Request'
    | 'Too Many Requests'
    | 'Internal Server Error'
    | 'Service Unavailable';
  /** The HTTP status, repeated. */
  status: 400 | 403 | 410 | 413 | 415 | 421 | 429 | 500 | 503;
  /** The error, from the published list. A page shows its own text for it, and treats a code it does not know by its HTTP status. */
  code:
    | 'bad_request'
    | 'invalid_answer'
    | 'forbidden'
    | 'interaction_expired'
    | 'content_too_large'
    | 'unsupported_media_type'
    | 'misdirected_request'
    | 'too_many_requests'
    | 'internal_error'
    | 'service_unavailable'
    | (string & {});
  /** The id the server logged the request under. A page shows it, so an operator can find the failure (ADR-020 §3). */
  trace_id: string;
}

/** Identifier-first sign-in (ADR-020 §3). Every identifier, known or unknown, gets the same next step, so the screen reveals nothing about which accounts exist (ADR-017 Decision 4). */
export interface IdentifierStep {
  type: 'urn:qauth:ia:identifier:v1-rc.0';
  params: IdentifierParams;
}

export type IdentifierParams = Record<string, never>;

/** An answer to `urn:qauth:ia:identifier:v1-rc.0`. */
export interface IdentifierAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:identifier:v1-rc.0';
  csrf: Csrf;
  /** The identifier: today an email address of at most 254 bytes in email syntax (ADR-017 Decision 3). The server normalises it before use. */
  login_hint: string;
}

/** The personal data of `urn:qauth:ia:identifier:v1-rc.0`. */
export interface IdentifierPersonal {
  type: 'urn:qauth:ia:identifier:v1-rc.0';
  data: IdentifierPersonalData;
}

export type IdentifierPersonalData = Record<string, never>;

/** The password factor. A rejected password, an unknown account and a disabled account give the same `invalid_credentials`, after the same timing floor (ADR-017 Decisions 3 and 4). Works without JavaScript: the form posts straight to the auth server with the step’s CSRF value (ADR-019 Decision 5). */
export interface PasswordStep {
  type: 'urn:qauth:ia:password:v1-rc.0';
  params: PasswordParams;
  error?: PasswordError;
}

export type PasswordParams = Record<string, never>;

/** Why the last answer to `urn:qauth:ia:password:v1-rc.0` was refused. A closed set. */
export type PasswordError = 'invalid_credentials';

/** An answer to `urn:qauth:ia:password:v1-rc.0`. */
export interface PasswordAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:password:v1-rc.0';
  csrf: Csrf;
  /** The password. The server refuses one longer than 256 UTF-16 code units before anything else (ADR-017 Decision 8). */
  password: string;
  /** The identifier: today an email address of at most 254 bytes in email syntax (ADR-017 Decision 3). The server normalises it before use. Sent only when the transaction holds no identifier yet: a page that asks for both at once. */
  login_hint?: string;
}

/** The personal data of `urn:qauth:ia:password:v1-rc.0`. */
export interface PasswordPersonal {
  type: 'urn:qauth:ia:password:v1-rc.0';
  data: PasswordPersonalData;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface PasswordPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

/** An emailed code proves control of a mailbox: it verifies a password account’s address and recovers an account. It is never a sign-in factor and adds no `amr` value (ADR-017 Decision 5). An answer with no `otp` asks for the code again. Works without JavaScript. */
export interface EmailCodeStep {
  type: 'urn:qauth:ia:email_code:v1-rc.0';
  params: EmailCodeParams;
  error?: EmailCodeError;
}

export interface EmailCodeParams {
  /** Why the code was sent, so one screen can say so: to verify the address, to recover the account, or (FiPA endpoint only; the Interaction API never offers it) to confirm a sign-in after the password. */
  purpose: 'verify_address' | 'recovery' | 'confirm_sign_in';
  /** How many digits the code has: six after a password, eight for recovery and registration. */
  length: 6 | 8;
  /** How many seconds the code stays valid. */
  expires_in: number;
  /** How many seconds until another code may be asked for. */
  resend_after: number;
}

/** Why the last answer to `urn:qauth:ia:email_code:v1-rc.0` was refused. A closed set. */
export type EmailCodeError = 'invalid_credentials' | 'code_expired';

/** An answer to `urn:qauth:ia:email_code:v1-rc.0`. */
export interface EmailCodeAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:email_code:v1-rc.0';
  csrf: Csrf;
  /** The code. Leave it out to ask for a new one. */
  otp?: string;
}

/** The personal data of `urn:qauth:ia:email_code:v1-rc.0`. */
export interface EmailCodePersonal {
  type: 'urn:qauth:ia:email_code:v1-rc.0';
  data: EmailCodePersonalData;
}

/** The address the code went to, when the transaction holds one. */
export interface EmailCodePersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

/** Sets a password through the one password policy (ADR-017 Decision 8): at registration, at the end of a reset, or when an admin or a breach-list match requires a new one (ADR-020 §3). The reasons of a refusal are returned, never prose. The page marks the field for password managers, with the identifier from the personal data as the username. Works without JavaScript. */
export interface NewPasswordStep {
  type: 'urn:qauth:ia:new_password:v1-rc.0';
  params: NewPasswordParams;
  error?: NewPasswordError;
}

export interface NewPasswordParams {
  /** Why a new password is asked for, so one screen can say so: a new account, a reset, or a required update. */
  purpose: 'register' | 'reset' | 'update_required';
  /** The shortest password the policy accepts, in code points. */
  min_length: number;
  /** The longest password the policy accepts. */
  max_length: number;
  /** After a refused answer: why the policy refused it. */
  reasons?: Array<'too_short' | 'too_long' | 'blocklisted' | 'too_weak'>;
}

/** Why the last answer to `urn:qauth:ia:new_password:v1-rc.0` was refused. A closed set. */
export type NewPasswordError = 'password_rejected';

/** An answer to `urn:qauth:ia:new_password:v1-rc.0`. */
export interface NewPasswordAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:new_password:v1-rc.0';
  csrf: Csrf;
  /** The new password. */
  new_password: string;
}

/** The personal data of `urn:qauth:ia:new_password:v1-rc.0`. */
export interface NewPasswordPersonal {
  type: 'urn:qauth:ia:new_password:v1-rc.0';
  data: NewPasswordPersonalData;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface NewPasswordPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

/** A path marker: answering it starts a reset. The next step is `email_code` with `purpose` `recovery` for every address, known or not; mail goes only to a known address with a password. A reset never unlocks an account whose strongest authenticator is stronger than email (ADR-017 Decision 8). */
export interface PasswordResetStep {
  type: 'urn:qauth:ia:password_reset:v1-rc.0';
  params: PasswordResetParams;
}

export type PasswordResetParams = Record<string, never>;

/** An answer to `urn:qauth:ia:password_reset:v1-rc.0`. */
export interface PasswordResetAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:password_reset:v1-rc.0';
  csrf: Csrf;
  /** The identifier: today an email address of at most 254 bytes in email syntax (ADR-017 Decision 3). The server normalises it before use. Sent only when the transaction holds no identifier yet. */
  login_hint?: string;
}

/** The personal data of `urn:qauth:ia:password_reset:v1-rc.0`. */
export interface PasswordResetPersonal {
  type: 'urn:qauth:ia:password_reset:v1-rc.0';
  data: PasswordResetPersonalData;
}

export type PasswordResetPersonalData = Record<string, never>;

/** A bot challenge, when a soft threshold requires one; the pending step resumes after it (ADR-017 Decisions 4 and 7). By default the built-in proof of work, whose script the ceremony app serves from the realm origin. An operator may name a hosted provider for the sign-up and sign-in pages only (ADR-019 Decision 5). A required challenge needs JavaScript and is never skipped. */
export interface CaptchaStep {
  type: 'urn:qauth:ia:captcha:v1-rc.0';
  params: CaptchaParams;
  error?: CaptchaError;
}

/** The challenge to solve: the built-in proof of work, or a hosted provider. */
export type CaptchaParams =
  | {
      /** The built-in proof of work. */
      provider: 'pow';
      /** The puzzle the engine issued. */
      challenge: string;
      /** How many leading zero bits the answer must produce. */
      difficulty: number;
    }
  | {
      /** The name the operator gave the hosted provider. */
      provider: string;
      /** The provider’s public site key. */
      site_key: string;
    };

/** Why the last answer to `urn:qauth:ia:captcha:v1-rc.0` was refused. A closed set. */
export type CaptchaError = 'captcha_failed';

/** An answer to `urn:qauth:ia:captcha:v1-rc.0`. */
export interface CaptchaAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:captcha:v1-rc.0';
  csrf: Csrf;
  /** The solution, or the provider’s token. */
  captcha_token: string;
}

/** The personal data of `urn:qauth:ia:captcha:v1-rc.0`. */
export interface CaptchaPersonal {
  type: 'urn:qauth:ia:captcha:v1-rc.0';
  data: CaptchaPersonalData;
}

export type CaptchaPersonalData = Record<string, never>;

/** Passkey sign-in: the WebAuthn Level 3 request options as JSON, for `PublicKeyCredential.parseRequestOptionsFromJSON()`. Discoverable credentials only: the options never carry `allowCredentials`, so the step read reveals no account’s passkeys (ADR-017 Decision 4, ADR-019 Decision 6). The engine checks that the passkey belongs to the transaction’s account. The RP ID is the realm’s host (ADR-019 Decision 2). Needs JavaScript. */
export interface WebauthnGetStep {
  type: 'urn:qauth:ia:webauthn_get:v1-rc.0';
  params: WebauthnGetParams;
  error?: WebauthnGetError;
}

export interface WebauthnGetParams {
  /** The challenge, at least 32 random bytes. */
  challenge: string;
  /** The relying party ID: the realm’s host. */
  rpId: string;
  /** How long the ceremony may take, in milliseconds. */
  timeout?: number;
  /** The server refuses an assertion without user verification. */
  userVerification: 'required';
}

/** Why the last answer to `urn:qauth:ia:webauthn_get:v1-rc.0` was refused. A closed set. */
export type WebauthnGetError = 'invalid_credentials';

/** An answer to `urn:qauth:ia:webauthn_get:v1-rc.0`. */
export interface WebauthnGetAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:webauthn_get:v1-rc.0';
  csrf: Csrf;
  /** The authentication response, `PublicKeyCredential.toJSON()` (WebAuthn Level 3), as a JSON string. It is a string on both transports, so a form post carries it in one field (ADR-017 Decision 3). */
  webauthn_response: string;
}

/** The personal data of `urn:qauth:ia:webauthn_get:v1-rc.0`. */
export interface WebauthnGetPersonal {
  type: 'urn:qauth:ia:webauthn_get:v1-rc.0';
  data: WebauthnGetPersonalData;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface WebauthnGetPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

/** Passkey enrolment. `options` is the WebAuthn Level 3 creation options as JSON without `user` and `excludeCredentials`, which are the account’s own data and come with the personal data; the page joins the two for `PublicKeyCredential.parseCreationOptionsFromJSON()`. The RP ID is the realm’s host and locks at the first enrolment (ADR-019 Decision 2). Enrolment adds no `amr` value. Needs JavaScript. */
export interface WebauthnCreateStep {
  type: 'urn:qauth:ia:webauthn_create:v1-rc.0';
  params: WebauthnCreateParams;
  error?: WebauthnCreateError;
}

export interface WebauthnCreateParams {
  /** Whether this is an offer the person may decline: an answer with no `webauthn_response` declines it. */
  optional: boolean;
  options: {
    /** The challenge, at least 32 random bytes. */
    challenge: string;
    rp: {
      /** The relying party ID: the realm’s host. */
      id: string;
      /** The realm’s display name. */
      name: string;
    };
    /** The COSE algorithms the server accepts, preferred first. */
    pubKeyCredParams: Array<{
      type: 'public-key';
      /** EdDSA, ES256 or RS256. */
      alg: -8 | -7 | -257;
    }>;
    /** How long the ceremony may take, in milliseconds. */
    timeout?: number;
    authenticatorSelection: {
      /** A passkey is discoverable. */
      residentKey: 'required';
      userVerification: 'required';
    };
    /** QAuth asks for no attestation and claims nothing about the key store. */
    attestation: 'none';
  };
}

/** Why the last answer to `urn:qauth:ia:webauthn_create:v1-rc.0` was refused. A closed set. */
export type WebauthnCreateError = 'invalid_credentials';

/** An answer to `urn:qauth:ia:webauthn_create:v1-rc.0`. */
export interface WebauthnCreateAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:webauthn_create:v1-rc.0';
  csrf: Csrf;
  /** The registration response, `PublicKeyCredential.toJSON()` (WebAuthn Level 3), as a JSON string. It is a string on both transports, so a form post carries it in one field (ADR-017 Decision 3). */
  webauthn_response?: string;
}

/** The personal data of `urn:qauth:ia:webauthn_create:v1-rc.0`. */
export interface WebauthnCreatePersonal {
  type: 'urn:qauth:ia:webauthn_create:v1-rc.0';
  data: WebauthnCreatePersonalData;
}

export interface WebauthnCreatePersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
  user: {
    /** The user handle: an opaque id, at most 64 bytes. */
    id: string;
    /** The account name the authenticator shows. */
    name: string;
    /** The display name the authenticator shows. */
    displayName: string;
  };
  /** The account’s passkeys, so the authenticator does not make a second one. */
  excludeCredentials: Array<{
    type: 'public-key';
    /** The credential id. */
    id: string;
    transports?: Array<'ble' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb'>;
  }>;
}

/** A TOTP second factor (RFC 6238) with the fixed parameters of ADR-020 §3: SHA-1, six digits, 30 seconds, one step of tolerance. An accepted code is never accepted twice (ADR-017 Decision 8). Works without JavaScript. */
export interface TotpStep {
  type: 'urn:qauth:ia:totp:v1-rc.0';
  params: TotpParams;
  error?: TotpError;
}

export interface TotpParams {
  /** How many digits the code has. */
  digits: 6;
}

/** Why the last answer to `urn:qauth:ia:totp:v1-rc.0` was refused. A closed set. */
export type TotpError = 'invalid_credentials';

/** An answer to `urn:qauth:ia:totp:v1-rc.0`. */
export interface TotpAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:totp:v1-rc.0';
  csrf: Csrf;
  /** The six digits the authenticator app shows. */
  otp: string;
}

/** The personal data of `urn:qauth:ia:totp:v1-rc.0`. */
export interface TotpPersonal {
  type: 'urn:qauth:ia:totp:v1-rc.0';
  data: TotpPersonalData;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface TotpPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

/** A recovery code stands in for a second factor after the first, or for the passkey of a passkey-only account. Only the hosted pages redeem one; the FiPA endpoint answers `redirect_to_web` for that path. It adds no `amr` value and never `mfa`, so a policy that needs a second factor makes the person bind a new one before the transaction completes (ADR-017 Decisions 4 and 8). Works without JavaScript. */
export interface RecoveryCodeStep {
  type: 'urn:qauth:ia:recovery_code:v1-rc.0';
  params: RecoveryCodeParams;
  error?: RecoveryCodeError;
}

export type RecoveryCodeParams = Record<string, never>;

/** Why the last answer to `urn:qauth:ia:recovery_code:v1-rc.0` was refused. A closed set. */
export type RecoveryCodeError = 'invalid_credentials';

/** An answer to `urn:qauth:ia:recovery_code:v1-rc.0`. */
export interface RecoveryCodeAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:recovery_code:v1-rc.0';
  csrf: Csrf;
  /** The code as the person typed it. The server ignores case, spaces and dashes before comparing. */
  recovery_code: string;
}

/** The personal data of `urn:qauth:ia:recovery_code:v1-rc.0`. */
export interface RecoveryCodePersonal {
  type: 'urn:qauth:ia:recovery_code:v1-rc.0';
  data: RecoveryCodePersonalData;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface RecoveryCodePersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

/** A new recovery-code set: issued at the first enrolment of a second factor, at the registration of a passkey-only account, and when the person regenerates the set (ADR-017 Decision 8). The codes are personal data, readable with the flow cookie only while this step is current, and never shown again. The answer confirms the person saved them. */
export interface RecoveryCodesStep {
  type: 'urn:qauth:ia:recovery_codes:v1-rc.0';
  params: RecoveryCodesParams;
}

export interface RecoveryCodesParams {
  /** How many codes the set holds. */
  count: 10;
}

/** An answer to `urn:qauth:ia:recovery_codes:v1-rc.0`. */
export interface RecoveryCodesAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:recovery_codes:v1-rc.0';
  csrf: Csrf;
  /** The person confirms they saved the codes. In a form post: `true`. */
  acknowledged: true;
}

/** The personal data of `urn:qauth:ia:recovery_codes:v1-rc.0`. */
export interface RecoveryCodesPersonal {
  type: 'urn:qauth:ia:recovery_codes:v1-rc.0';
  data: RecoveryCodesPersonalData;
}

export interface RecoveryCodesPersonalData {
  /** The codes, each usable once. */
  codes: string[];
}

/** TOTP enrolment, with the fixed parameters of ADR-020 §3. The secret is personal data, read once with the flow cookie; it is bound only after a first valid code (ADR-017 Decision 8). A password-only account’s first binding also needs a code mailed to its address in the same transaction, and an unclaimed account never reaches this step. Enrolment adds no `amr` value. The page shows the secret as a QR code and as text. */
export interface TotpSetupStep {
  type: 'urn:qauth:ia:totp_setup:v1-rc.0';
  params: TotpSetupParams;
  error?: TotpSetupError;
}

export interface TotpSetupParams {
  /** The HMAC algorithm. */
  algorithm: 'SHA1';
  /** How many digits a code has. */
  digits: 6;
  /** How many seconds a code lasts. */
  period: 30;
}

/** Why the last answer to `urn:qauth:ia:totp_setup:v1-rc.0` was refused. A closed set. */
export type TotpSetupError = 'invalid_credentials';

/** An answer to `urn:qauth:ia:totp_setup:v1-rc.0`. */
export interface TotpSetupAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:totp_setup:v1-rc.0';
  csrf: Csrf;
  /** The six digits the authenticator app shows. */
  otp: string;
}

/** The personal data of `urn:qauth:ia:totp_setup:v1-rc.0`. */
export interface TotpSetupPersonal {
  type: 'urn:qauth:ia:totp_setup:v1-rc.0';
  data: TotpSetupPersonalData;
}

export interface TotpSetupPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
  /** The shared secret, 160 bits in base32 (RFC 4648 §6), unpadded. */
  secret: string;
  /** The same secret as an `otpauth://` URI, for the QR code. */
  otpauth_uri: string;
}

/** The OAuth consent decision (#629). The interaction’s `client` names the client, verified domain first (ADR-019 Decision 6). The grant is exactly the scope set shown here, which the interaction holds: the answer cannot add a scope. A dangerous scope and `prompt=consent` always reach this step; a first-party client may skip it only through the administrative waiver (ADR-017 Decision 9). Works without JavaScript. */
export interface ConsentStep {
  type: 'urn:qauth:ia:consent:v1-rc.0';
  params: ConsentParams;
}

export interface ConsentParams {
  /** The scopes asked for, in the order the screen lists them. */
  scopes: Array<{
    /** The scope value (RFC 6749 §3.3), from its alphabet without `<` and `>`. A requested scope outside it never reaches this step: the request is refused first. */
    scope: string;
    /** The consent text the realm’s scope catalog holds for this scope, in the interaction’s locale. Absent when the catalog has none: the screen shows the scope value. */
    text?: string;
    /** Whether the realm flagged the scope as sensitive. */
    sensitive: boolean;
    /** Whether the scope is dangerous (`write:*`, `agent:admin`, `agent:exec`): it always needs consent and a fresh sign-in. */
    dangerous: boolean;
  }>;
  /** Where the tokens may be used: the resource indicators (RFC 8707) of the request. */
  resources: string[];
  /** Whether "remember this decision" starts checked. */
  remember_default: boolean;
}

/** An answer to `urn:qauth:ia:consent:v1-rc.0`. */
export interface ConsentAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:consent:v1-rc.0';
  csrf: Csrf;
  /** The decision. */
  decision: 'allow' | 'deny';
  /** Whether to remember an `allow` for later requests that fit it. In a form post the checkbox sends `true`, and its absence means `false`. */
  remember?: boolean;
}

/** The personal data of `urn:qauth:ia:consent:v1-rc.0`. */
export interface ConsentPersonal {
  type: 'urn:qauth:ia:consent:v1-rc.0';
  data: ConsentPersonalData;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface ConsentPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

/** The account chooser for `prompt=select_account`, when the browser holds sessions for several accounts of the realm (ADR-019 Decision 3, ADR-020 §3). The list is personal data. "Use another account" answers the `identifier` step, offered beside this one, which starts a new interaction for the same authorization request; nothing proved for one account carries over to another (#592). Needs JavaScript, to read the list. */
export interface SelectAccountStep {
  type: 'urn:qauth:ia:select_account:v1-rc.0';
  params: SelectAccountParams;
  error?: SelectAccountError;
}

export type SelectAccountParams = Record<string, never>;

/** Why the last answer to `urn:qauth:ia:select_account:v1-rc.0` was refused. A closed set. */
export type SelectAccountError = 'account_unavailable';

/** An answer to `urn:qauth:ia:select_account:v1-rc.0`. */
export interface SelectAccountAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:select_account:v1-rc.0';
  csrf: Csrf;
  /** The `account` reference of the chosen entry. */
  account: string;
}

/** The personal data of `urn:qauth:ia:select_account:v1-rc.0`. */
export interface SelectAccountPersonal {
  type: 'urn:qauth:ia:select_account:v1-rc.0';
  data: SelectAccountPersonalData;
}

export interface SelectAccountPersonalData {
  /** The accounts the browser holds a session for, the current one first. */
  accounts: Array<{
    /** An opaque reference to the account’s session, valid for this interaction only. */
    account: string;
    /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
    identifier: string;
    /** Whether this is the account the browser last used. */
    current: boolean;
  }>;
}

/** Code entry for the OAuth 2.0 device authorization grant (RFC 8628 §3.3). Unknown, expired and used codes give the same `invalid_user_code`. Entry is rate-limited per code, per session and per address. A person who arrives through `verification_uri_complete` skips this step and still confirms on `device_confirm` (ADR-020 §3). Works without JavaScript. */
export interface DeviceCodeStep {
  type: 'urn:qauth:ia:device_code:v1-rc.0';
  params: DeviceCodeParams;
  error?: DeviceCodeError;
}

export interface DeviceCodeParams {
  /** How many characters the code has, without the dash. */
  length: 8;
}

/** Why the last answer to `urn:qauth:ia:device_code:v1-rc.0` was refused. A closed set. */
export type DeviceCodeError = 'invalid_user_code';

/** An answer to `urn:qauth:ia:device_code:v1-rc.0`. */
export interface DeviceCodeAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:device_code:v1-rc.0';
  csrf: Csrf;
  /** The code as typed. The server ignores case, spaces and dashes (RFC 8628 §6.1). */
  user_code: string;
}

/** The personal data of `urn:qauth:ia:device_code:v1-rc.0`. */
export interface DeviceCodePersonal {
  type: 'urn:qauth:ia:device_code:v1-rc.0';
  data: DeviceCodePersonalData;
}

export type DeviceCodePersonalData = Record<string, never>;

/** The explicit confirmation of a device authorization, always asked, also after `verification_uri_complete` (ADR-020 §3). The screen warns that nobody else should have given the person the code, and shows where the request came from: the requesting device’s approximate location, network and user agent, which are personal data, and its start time. The consent step always follows, even for a client that may skip consent elsewhere. Works without JavaScript, without the device details. */
export interface DeviceConfirmStep {
  type: 'urn:qauth:ia:device_confirm:v1-rc.0';
  params: DeviceConfirmParams;
}

export interface DeviceConfirmParams {
  /** The code being confirmed, so the person can compare it with the device. */
  user_code: string;
  /** When the device started the request. */
  requested_at: string;
}

/** An answer to `urn:qauth:ia:device_confirm:v1-rc.0`. */
export interface DeviceConfirmAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:device_confirm:v1-rc.0';
  csrf: Csrf;
  /** The decision. */
  decision: 'confirm' | 'deny';
}

/** The personal data of `urn:qauth:ia:device_confirm:v1-rc.0`. */
export interface DeviceConfirmPersonal {
  type: 'urn:qauth:ia:device_confirm:v1-rc.0';
  data: DeviceConfirmPersonalData;
}

export interface DeviceConfirmPersonalData {
  /** Where the requesting address is, approximately. Absent when the lookup knows nothing. */
  location?: {
    /** The ISO 3166-1 alpha-2 country of the requesting address. */
    country?: string;
    /** The region of the requesting address. */
    region?: string;
  };
  /** The network the request came from. */
  network?: {
    /** The autonomous system number of the requesting address. */
    asn?: number;
    /** The name of that network. */
    name?: string;
  };
  /** The user agent the device declared, cut and stripped. The device chose it, so the screen marks it as declared. */
  user_agent?: string;
}

/** The confirmation of an RP-initiated logout (ADR-019 Decision 4). The interaction’s `client` names the app that asked, when the request identified one. A browser may hold several accounts’ sessions, so the person signs out of this account or of every account on the browser (ADR-019 Decision 3). Works without JavaScript, without the account list. */
export interface LogoutConfirmStep {
  type: 'urn:qauth:ia:logout_confirm:v1-rc.0';
  params: LogoutConfirmParams;
}

export type LogoutConfirmParams = Record<string, never>;

/** An answer to `urn:qauth:ia:logout_confirm:v1-rc.0`. */
export interface LogoutConfirmAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:logout_confirm:v1-rc.0';
  csrf: Csrf;
  /** Sign out of this account, of every account on the browser, or stay signed in. */
  decision: 'logout' | 'logout_all' | 'stay';
}

/** The personal data of `urn:qauth:ia:logout_confirm:v1-rc.0`. */
export interface LogoutConfirmPersonal {
  type: 'urn:qauth:ia:logout_confirm:v1-rc.0';
  data: LogoutConfirmPersonalData;
}

export interface LogoutConfirmPersonalData {
  /** The accounts signed in on this browser, the one being signed out first. */
  accounts: Array<{
    /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
    identifier: string;
    /** Whether this is the account the logout request is for. */
    current: boolean;
  }>;
}

/** Every operation: its method, path, path parameters, JSON request body and response bodies by status. */
export interface Operations {
  'interactions.get': {
    method: 'GET';
    path: '/interaction/v1-rc.0/{interactionId}';
    pathParams: { interactionId: InteractionId };
    requestBody: never;
    responses: {
      200: Interaction;
      410: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'interactions.personal.get': {
    method: 'GET';
    path: '/interaction/v1-rc.0/{interactionId}/personal';
    pathParams: { interactionId: InteractionId };
    requestBody: never;
    responses: {
      200: PersonalData;
      410: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'interactions.answer': {
    method: 'POST';
    path: '/interaction/v1-rc.0/{interactionId}/answer';
    pathParams: { interactionId: InteractionId };
    requestBody: AnswerRequest;
    responses: {
      200: AnswerResult;
      303: undefined;
      400: Problem;
      403: Problem;
      410: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'interactions.cancel': {
    method: 'POST';
    path: '/interaction/v1-rc.0/{interactionId}/cancel';
    pathParams: { interactionId: InteractionId };
    requestBody: CancelRequest;
    responses: {
      200: RedirectResult;
      303: undefined;
      400: Problem;
      403: Problem;
      410: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
}

/** What each operation needs, from the document's `x-qauth-flow-cookie` and `x-qauth-csrf`. */
export const OPERATIONS = {
  'interactions.get': {
    method: 'GET',
    path: '/interaction/v1-rc.0/{interactionId}',
    flowCookie: false,
    csrf: false,
    statuses: [200, 410, 421, 429, 500, 503],
  },
  'interactions.personal.get': {
    method: 'GET',
    path: '/interaction/v1-rc.0/{interactionId}/personal',
    flowCookie: true,
    csrf: false,
    statuses: [200, 410, 421, 429, 500, 503],
  },
  'interactions.answer': {
    method: 'POST',
    path: '/interaction/v1-rc.0/{interactionId}/answer',
    flowCookie: true,
    csrf: true,
    statuses: [200, 303, 400, 403, 410, 413, 415, 421, 429, 500, 503],
  },
  'interactions.cancel': {
    method: 'POST',
    path: '/interaction/v1-rc.0/{interactionId}/cancel',
    flowCookie: true,
    csrf: true,
    statuses: [200, 303, 400, 403, 410, 413, 415, 421, 429, 500, 503],
  },
} as const;

/**
 * A client of the Interaction API. In a browser, leave `baseUrl` out: the API
 * is same-origin, and the flow cookie travels with the request. On the ceremony
 * app's server, set it to the auth server's address; that side holds no flow
 * cookie, so it can only read the current step.
 */
export function createInteractionClient(options: InteractionClientOptions = {}) {
  return {
    /** Read the current step: `interactions.get`. */
    interactionsGet: (pathParams: Operations['interactions.get']['pathParams'], init?: CallInit) =>
      callOperation<Operations['interactions.get']>(
        options,
        OPERATIONS['interactions.get'],
        pathParams,
        undefined,
        init
      ),
    /** Read the personal data of the current step: `interactions.personal.get`. */
    interactionsPersonalGet: (
      pathParams: Operations['interactions.personal.get']['pathParams'],
      init?: CallInit
    ) =>
      callOperation<Operations['interactions.personal.get']>(
        options,
        OPERATIONS['interactions.personal.get'],
        pathParams,
        undefined,
        init
      ),
    /** Answer the current step: `interactions.answer`. */
    interactionsAnswer: (
      pathParams: Operations['interactions.answer']['pathParams'],
      body: Operations['interactions.answer']['requestBody'],
      init?: CallInit
    ) =>
      callOperation<Operations['interactions.answer']>(
        options,
        OPERATIONS['interactions.answer'],
        pathParams,
        body,
        init
      ),
    /** Cancel the interaction: `interactions.cancel`. */
    interactionsCancel: (
      pathParams: Operations['interactions.cancel']['pathParams'],
      body: Operations['interactions.cancel']['requestBody'],
      init?: CallInit
    ) =>
      callOperation<Operations['interactions.cancel']>(
        options,
        OPERATIONS['interactions.cancel'],
        pathParams,
        body,
        init
      ),
  };
}

export type InteractionClient = ReturnType<typeof createInteractionClient>;
