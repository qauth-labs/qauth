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

/** An interaction as its current step shows it: the step, the alternatives and their params, a CSRF value for one answer, who the client is and the realm’s brand. No personal data. The step grammar’s part has the shape of the FiPA endpoint’s answer (ADR-017 Decision 3): `step` is its `interaction_type_required`, `step` and `alternatives` its `qauth_interaction_types_offered`, `params` its `qauth_interaction_params` and `error` its `qauth_interaction_error`. */
export interface Interaction {
  /** The current step: the one the engine asks for. */
  step: StepName;
  /** Why the last answer to the current step was refused, from that step’s closed error set. Absent otherwise. */
  error?: StepError;
  /** The other steps the engine accepts as the next answer, preferred first: "try another way", the paths a page links to (a reset, a resend), and the account switch. Never the current step. Before a first factor succeeds, the list holds only what the same request would offer every account, so it reveals no account’s methods; after it, that account’s remaining methods (ADR-017 Decision 4). */
  alternatives: StepName[];
  params: StepParams;
  csrf: Csrf;
  client?: ClientDisplay;
  brand: Brand;
  /** The `ui_locales` of the authorization request, validated, in order. */
  uiLocales?: string[];
  /** When the interaction expires. */
  expiresAt: string;
}

/** A step name, `urn:qauth:ia:<name>:v1-rc.0`. A page shows its error page for a step it does not know. */
export type StepName =
  | 'urn:qauth:ia:identifier:v1-rc.0'
  | 'urn:qauth:ia:password:v1-rc.0'
  | 'urn:qauth:ia:email_code:v1-rc.0'
  | 'urn:qauth:ia:new_password:v1-rc.0'
  | 'urn:qauth:ia:password_reset:v1-rc.0'
  | 'urn:qauth:ia:captcha:v1-rc.0'
  | 'urn:qauth:ia:webauthn_get:v1-rc.0'
  | 'urn:qauth:ia:webauthn_create:v1-rc.0'
  | 'urn:qauth:ia:totp:v1-rc.0'
  | 'urn:qauth:ia:recovery_code:v1-rc.0'
  | 'urn:qauth:ia:recovery_codes:v1-rc.0'
  | 'urn:qauth:ia:totp_setup:v1-rc.0'
  | 'urn:qauth:ia:consent:v1-rc.0'
  | 'urn:qauth:ia:select_account:v1-rc.0'
  | 'urn:qauth:ia:device_code:v1-rc.0'
  | 'urn:qauth:ia:device_confirm:v1-rc.0'
  | 'urn:qauth:ia:logout_confirm:v1-rc.0'
  | (string & {});

/** Why an answer was refused. Each step names its own closed set (`x-qauth-step` beside its params, and its schema file). */
export type StepError =
  | 'invalid_credentials'
  | 'code_expired'
  | 'password_rejected'
  | 'captcha_failed'
  | 'account_unavailable'
  | 'invalid_user_code'
  | (string & {});

/** The params of the offered steps, keyed by step name: the current step’s and each alternative’s. What any reader of the interaction id may see. */
export interface StepParams {
  'urn:qauth:ia:identifier:v1-rc.0'?: IdentifierParams;
  'urn:qauth:ia:password:v1-rc.0'?: PasswordParams;
  'urn:qauth:ia:email_code:v1-rc.0'?: EmailCodeParams;
  'urn:qauth:ia:new_password:v1-rc.0'?: NewPasswordParams;
  'urn:qauth:ia:password_reset:v1-rc.0'?: PasswordResetParams;
  'urn:qauth:ia:captcha:v1-rc.0'?: CaptchaParams;
  'urn:qauth:ia:webauthn_get:v1-rc.0'?: WebauthnGetParams;
  'urn:qauth:ia:webauthn_create:v1-rc.0'?: WebauthnCreateParams;
  'urn:qauth:ia:totp:v1-rc.0'?: TotpParams;
  'urn:qauth:ia:recovery_code:v1-rc.0'?: RecoveryCodeParams;
  'urn:qauth:ia:recovery_codes:v1-rc.0'?: RecoveryCodesParams;
  'urn:qauth:ia:totp_setup:v1-rc.0'?: TotpSetupParams;
  'urn:qauth:ia:consent:v1-rc.0'?: ConsentParams;
  'urn:qauth:ia:select_account:v1-rc.0'?: SelectAccountParams;
  'urn:qauth:ia:device_code:v1-rc.0'?: DeviceCodeParams;
  'urn:qauth:ia:device_confirm:v1-rc.0'?: DeviceConfirmParams;
  'urn:qauth:ia:logout_confirm:v1-rc.0'?: LogoutConfirmParams;
}

/** An answer to one step, by its name: the envelope’s `type` and `csrf`, and the step’s answer fields. A new step adds a variant, which widens what the server accepts. */
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
  /** Where the browser goes now: the authorization response to the client, the post-logout redirect, the ceremony app’s page of a new interaction (after an account switch), or a page of the ceremony app when no client waits, as at the end of a device authorization. Taken from the interaction record and the realm, never from the request. */
  location: string;
}

/** Cancel the interaction. The client gets `access_denied` with its `state` and `iss`; a logout ends with the person still signed in. */
export interface CancelRequest {
  csrf: Csrf;
}

/** The personal data of the current step: only the browser that holds the flow cookie reads it. */
export interface PersonalData {
  /** The current step, whose personal data this is. */
  step: StepName;
  data: StepPersonalData;
}

/** The current step’s personal data, under its step name. Empty for a step that has none. */
export interface StepPersonalData {
  'urn:qauth:ia:identifier:v1-rc.0'?: IdentifierPersonalData;
  'urn:qauth:ia:password:v1-rc.0'?: PasswordPersonalData;
  'urn:qauth:ia:email_code:v1-rc.0'?: EmailCodePersonalData;
  'urn:qauth:ia:new_password:v1-rc.0'?: NewPasswordPersonalData;
  'urn:qauth:ia:password_reset:v1-rc.0'?: PasswordResetPersonalData;
  'urn:qauth:ia:captcha:v1-rc.0'?: CaptchaPersonalData;
  'urn:qauth:ia:webauthn_get:v1-rc.0'?: WebauthnGetPersonalData;
  'urn:qauth:ia:webauthn_create:v1-rc.0'?: WebauthnCreatePersonalData;
  'urn:qauth:ia:totp:v1-rc.0'?: TotpPersonalData;
  'urn:qauth:ia:recovery_code:v1-rc.0'?: RecoveryCodePersonalData;
  'urn:qauth:ia:recovery_codes:v1-rc.0'?: RecoveryCodesPersonalData;
  'urn:qauth:ia:totp_setup:v1-rc.0'?: TotpSetupPersonalData;
  'urn:qauth:ia:consent:v1-rc.0'?: ConsentPersonalData;
  'urn:qauth:ia:select_account:v1-rc.0'?: SelectAccountPersonalData;
  'urn:qauth:ia:device_code:v1-rc.0'?: DeviceCodePersonalData;
  'urn:qauth:ia:device_confirm:v1-rc.0'?: DeviceConfirmPersonalData;
  'urn:qauth:ia:logout_confirm:v1-rc.0'?: LogoutConfirmPersonalData;
}

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
  /** RFC 9457 §3.1.1. `about:blank` today: no type beyond the HTTP status. A code may get its own type URI later, so a page branches on `code`, never on `type`. */
  type: string;
  /** The HTTP status phrase. Not for branching, and not for a screen. */
  title: string;
  /** The HTTP status, repeated. */
  status: number;
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
  /** Never sent: no prose. */
  detail?: never;
  /** Never sent. */
  instance?: never;
  /** Never sent: a refused answer comes back as its step’s `error`. */
  errors?: never;
}

export type IdentifierParams = Record<string, never>;

/** An answer to `urn:qauth:ia:identifier:v1-rc.0`. */
export interface IdentifierAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:identifier:v1-rc.0';
  csrf: Csrf;
  /** The identifier: today an email address of at most 254 bytes in UTF-8 (ADR-017 Decision 3). The schema counts characters; the server counts bytes, checks the full email syntax and normalises the address before use. */
  login_hint: string;
}

export type IdentifierPersonalData = Record<string, never>;

export type PasswordParams = Record<string, never>;

/** An answer to `urn:qauth:ia:password:v1-rc.0`. */
export interface PasswordAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:password:v1-rc.0';
  csrf: Csrf;
  /** The password. The server refuses one longer than 256 UTF-16 code units before anything else (ADR-017 Decision 8). */
  password: string;
  /** The identifier: today an email address of at most 254 bytes in UTF-8 (ADR-017 Decision 3). The schema counts characters; the server counts bytes, checks the full email syntax and normalises the address before use. Sent only when the transaction holds no identifier yet: a page that asks for both at once. */
  login_hint?: string;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface PasswordPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
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

/** An answer to `urn:qauth:ia:email_code:v1-rc.0`. */
export interface EmailCodeAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:email_code:v1-rc.0';
  csrf: Csrf;
  /** The code. Leave it out to ask for a new one. */
  otp?: string;
}

/** The address the code went to, when the transaction holds one. */
export interface EmailCodePersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
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

/** An answer to `urn:qauth:ia:new_password:v1-rc.0`. */
export interface NewPasswordAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:new_password:v1-rc.0';
  csrf: Csrf;
  /** The new password. */
  new_password: string;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface NewPasswordPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

export type PasswordResetParams = Record<string, never>;

/** An answer to `urn:qauth:ia:password_reset:v1-rc.0`. */
export interface PasswordResetAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:password_reset:v1-rc.0';
  csrf: Csrf;
  /** The identifier: today an email address of at most 254 bytes in UTF-8 (ADR-017 Decision 3). The schema counts characters; the server counts bytes, checks the full email syntax and normalises the address before use. Sent only when the transaction holds no identifier yet. */
  login_hint?: string;
}

export type PasswordResetPersonalData = Record<string, never>;

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
      /** A hosted provider the operator named. */
      provider: 'hosted';
      /** The name the operator gave the hosted provider. */
      name: string;
      /** The provider’s public site key. */
      site_key: string;
    };

/** An answer to `urn:qauth:ia:captcha:v1-rc.0`. */
export interface CaptchaAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:captcha:v1-rc.0';
  csrf: Csrf;
  /** The solution, or the provider’s token: printable ASCII, so 4096 characters are 4096 bytes. */
  captcha_token: string;
}

export type CaptchaPersonalData = Record<string, never>;

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

/** An answer to `urn:qauth:ia:webauthn_get:v1-rc.0`. */
export interface WebauthnGetAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:webauthn_get:v1-rc.0';
  csrf: Csrf;
  /** The authentication response, `PublicKeyCredential.toJSON()` (WebAuthn Level 3), as a JSON string. It is a string on both transports, so a form post carries it in one field (ADR-017 Decision 3). */
  webauthn_response: string;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface WebauthnGetPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
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

/** An answer to `urn:qauth:ia:webauthn_create:v1-rc.0`. */
export interface WebauthnCreateAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:webauthn_create:v1-rc.0';
  csrf: Csrf;
  /** The registration response, `PublicKeyCredential.toJSON()` (WebAuthn Level 3), as a JSON string. It is a string on both transports, so a form post carries it in one field (ADR-017 Decision 3). */
  webauthn_response?: string;
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

export interface TotpParams {
  /** How many digits the code has. */
  digits: 6;
}

/** An answer to `urn:qauth:ia:totp:v1-rc.0`. */
export interface TotpAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:totp:v1-rc.0';
  csrf: Csrf;
  /** The six digits the authenticator app shows. */
  otp: string;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface TotpPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

export type RecoveryCodeParams = Record<string, never>;

/** An answer to `urn:qauth:ia:recovery_code:v1-rc.0`. */
export interface RecoveryCodeAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:recovery_code:v1-rc.0';
  csrf: Csrf;
  /** The code as the person typed it. The server ignores case, spaces and dashes before comparing. */
  recovery_code: string;
}

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface RecoveryCodePersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
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

export interface RecoveryCodesPersonalData {
  /** The codes, each usable once. */
  codes: string[];
}

export interface TotpSetupParams {
  /** The HMAC algorithm. */
  algorithm: 'SHA1';
  /** How many digits a code has. */
  digits: 6;
  /** How many seconds a code lasts. */
  period: 30;
}

/** An answer to `urn:qauth:ia:totp_setup:v1-rc.0`. */
export interface TotpSetupAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:totp_setup:v1-rc.0';
  csrf: Csrf;
  /** The six digits the authenticator app shows. */
  otp: string;
}

export interface TotpSetupPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
  /** The shared secret, 160 bits in base32 (RFC 4648 §6), unpadded. */
  secret: string;
  /** The same secret as an `otpauth://` URI, for the QR code. */
  otpauth_uri: string;
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

/** Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier. */
export interface ConsentPersonalData {
  /** The identifier of the account this transaction is for, as the person gave it or as the account holds it. Personal data: only the personal-data read returns it. */
  identifier?: string;
}

export type SelectAccountParams = Record<string, never>;

/** An answer to `urn:qauth:ia:select_account:v1-rc.0`. */
export interface SelectAccountAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:select_account:v1-rc.0';
  csrf: Csrf;
  /** The `account` reference of the chosen entry. */
  account: string;
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

export interface DeviceCodeParams {
  /** How many characters the code has, without the dash. */
  length: 8;
}

/** An answer to `urn:qauth:ia:device_code:v1-rc.0`. */
export interface DeviceCodeAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:device_code:v1-rc.0';
  csrf: Csrf;
  /** The code as typed. The server ignores case, spaces and dashes (RFC 8628 §6.1). */
  user_code: string;
}

export type DeviceCodePersonalData = Record<string, never>;

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

export type LogoutConfirmParams = Record<string, never>;

/** An answer to `urn:qauth:ia:logout_confirm:v1-rc.0`. */
export interface LogoutConfirmAnswer {
  /** The step this request answers. */
  type: 'urn:qauth:ia:logout_confirm:v1-rc.0';
  csrf: Csrf;
  /** Sign out of this account, of every account on the browser, or stay signed in. */
  decision: 'logout' | 'logout_all' | 'stay';
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
    pathPatterns: { interactionId: '^[A-Za-z0-9_-]{43}$' },
    flowCookie: false,
    csrf: false,
    statuses: [200, 410, 421, 429, 500, 503],
  },
  'interactions.personal.get': {
    method: 'GET',
    path: '/interaction/v1-rc.0/{interactionId}/personal',
    pathPatterns: { interactionId: '^[A-Za-z0-9_-]{43}$' },
    flowCookie: true,
    csrf: false,
    statuses: [200, 410, 421, 429, 500, 503],
  },
  'interactions.answer': {
    method: 'POST',
    path: '/interaction/v1-rc.0/{interactionId}/answer',
    pathPatterns: { interactionId: '^[A-Za-z0-9_-]{43}$' },
    flowCookie: true,
    csrf: true,
    statuses: [200, 303, 400, 403, 410, 413, 415, 421, 429, 500, 503],
  },
  'interactions.cancel': {
    method: 'POST',
    path: '/interaction/v1-rc.0/{interactionId}/cancel',
    pathPatterns: { interactionId: '^[A-Za-z0-9_-]{43}$' },
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
