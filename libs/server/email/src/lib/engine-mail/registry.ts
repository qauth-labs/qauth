import { createElement, type ReactElement } from 'react';

import { formatDuration } from '../format-duration';
import {
  ENGINE_ACCOUNT_EXISTS_SUBJECT,
  EngineAccountExistsEmail,
} from '../templates/engine/account-exists';
import { CodeEmail, codeEmailSubject, type MailCodePurpose } from '../templates/engine/code-email';
import { PASSKEY_ADDED_SUBJECT, PasskeyAddedEmail } from '../templates/engine/passkey-added';
import {
  PASSWORD_CHANGED_SUBJECT,
  PasswordChangedEmail,
} from '../templates/engine/password-changed';
import {
  PASSWORD_DISABLED_SUBJECT,
  PasswordDisabledEmail,
} from '../templates/engine/password-disabled';
import {
  RECOVERY_CODE_USED_SUBJECT,
  RECOVERY_CODES_FAILED_SUBJECT,
  RECOVERY_CODES_REGENERATED_SUBJECT,
  RecoveryCodesFailedEmail,
  RecoveryCodesRegeneratedEmail,
  RecoveryCodeUsedEmail,
} from '../templates/engine/recovery-codes';
import {
  type MailPassFlow,
  SEND_CEILING_SUBJECT,
  SendCeilingEmail,
} from '../templates/engine/send-ceiling';
import { renderEmail, renderEmailText } from '../templates/render';
import type { MailBrand } from './brand';
import { isMailBaseUrl, isMailPass, mailPassUrl } from './links';

/**
 * THE ENGINE'S MAIL TEMPLATES (PRO-14, #637; ADR-017 Decisions 5 and 7,
 * ADR-020 §3 "Emails").
 *
 * One typed registry of fixed English templates: a mail names its template
 * and carries that template's data, and nothing else reaches the text. The
 * realm's brand sets the look (`brand.ts`); every link starts at the realm's
 * issuer (`links.ts`).
 *
 * Each template says two things the sender acts on:
 *
 * - whether the mail carries a code: only such a mail counts toward the send
 *   caps, and only such a mail may be quietly dropped at a cap (ADR-017
 *   Decision 5: "Mail that carries no code does not count toward these caps
 *   and is never suppressed by them");
 * - whether a realm may switch it off. None of these may be: the code and
 *   "account exists" mails are steps of a flow, "password changed" and the
 *   recovery codes' notices (#649: a code used, a set replaced, 100 wrong
 *   codes in a row) are notices about a credential, and the send-ceiling and
 *   password-disabled notices carry the pass that keeps the owner's reset
 *   open (ADR-020 §3 "Emails": they "always go out").
 */

/** What a mailed code proves, by the `email_code` step's purpose. */
export type { MailCodePurpose } from '../templates/engine/code-email';
/** What a mailed pass starts. */
export type { MailPassFlow } from '../templates/engine/send-ceiling';

/** A mail of the engine: its template, and that template's data. */
export type EngineMail =
  | {
      readonly template: 'code';
      readonly purpose: MailCodePurpose;
      /** 6 or 8 digits, as the purpose takes (ADR-017 Decision 5). */
      readonly code: string;
      readonly expiresInSeconds: number;
    }
  | {
      readonly template: 'account_exists';
      /** The registration's code, when the start goes on to help the owner sign in. */
      readonly code?: string;
      readonly expiresInSeconds?: number;
    }
  | { readonly template: 'password_changed' }
  | {
      readonly template: 'password_disabled';
      /** The pass that takes the owner's reset past every per-address send tier. */
      readonly pass: string;
      readonly passExpiresInSeconds: number;
    }
  | {
      readonly template: 'send_ceiling';
      /** What the pass starts: a reset of the account, or the address's registration. */
      readonly flow: MailPassFlow;
      readonly pass: string;
      readonly passExpiresInSeconds: number;
    }
  | {
      readonly template: 'recovery_code_used';
      /** How many codes of the set are left unused after this one, 0 to 10. */
      readonly unusedCodes: number;
    }
  | { readonly template: 'recovery_codes_regenerated' }
  | { readonly template: 'recovery_codes_failed' }
  | { readonly template: 'passkey_added' };

/** The name of an engine mail template. */
export type EngineMailName = EngineMail['template'];

/** Where a mail's links start and how it looks. */
export interface EngineMailContext {
  /** The realm's issuer, from the realm row: every link and the logo start here. */
  readonly baseUrl: string;
  readonly brand: MailBrand;
}

/** A rendered mail, ready for a transport. */
export interface RenderedEngineMail {
  readonly subject: string;
  readonly html: string;
  readonly text: string;
}

/** A mail whose data does not fit its template: a caller's bug, never sent. */
export class EngineMailError extends Error {
  override readonly name = 'EngineMailError';
}

type MailOf<Name extends EngineMailName> = Extract<EngineMail, { template: Name }>;

/** One template of the registry. */
export interface EngineMailTemplate<Name extends EngineMailName> {
  /** Whether a realm may switch this mail off (#693 adds the realm setting). */
  readonly realmMaySwitchOff: boolean;
  /** Whether the mail carries a pass: such a mail is never counted or suppressed. */
  readonly carriesPass: boolean;
  /** Whether this mail carries a code, and so counts toward the send caps. */
  carriesCode(mail: MailOf<Name>): boolean;
  subject(mail: MailOf<Name>): string;
  /** The checked data's element; throws {@link EngineMailError} for data out of shape. */
  element(mail: MailOf<Name>, context: EngineMailContext): ReactElement;
}

/** How many digits a code may have, by purpose (ADR-017 Decision 5; the step grammar's rule). */
const CODE_LENGTHS: Readonly<Record<MailCodePurpose, readonly number[]>> = Object.freeze({
  verify_account: [6, 8],
  recovery: [8],
  confirm_sign_in: [6],
});

/** A code lives at most 10 minutes (ADR-017 Decision 5). */
const CODE_MAX_EXPIRES_IN_SECONDS = 600;
/** A pass lives at most 24 hours (ADR-017 Decision 5). */
const PASS_MAX_EXPIRES_IN_SECONDS = 86_400;

function checkCode(code: unknown, lengths: readonly number[]): string {
  if (typeof code !== 'string' || !/^[0-9]+$/.test(code) || !lengths.includes(code.length)) {
    throw new EngineMailError(`a mailed code has ${lengths.join(' or ')} digits`);
  }
  return code;
}

function checkLifetime(seconds: unknown, max: number, what: string): string {
  if (typeof seconds !== 'number' || !Number.isInteger(seconds) || seconds < 1 || seconds > max) {
    throw new EngineMailError(`${what} lives from 1 to ${max} seconds`);
  }
  return formatDuration(seconds);
}

/** A set holds 10 codes (#649), so at most 10 are left. */
function checkUnusedCodes(count: unknown): number {
  if (typeof count !== 'number' || !Number.isInteger(count) || count < 0 || count > 10) {
    throw new EngineMailError('a set has 0 to 10 unused codes left');
  }
  return count;
}

function checkPass(pass: unknown): string {
  if (!isMailPass(pass)) throw new EngineMailError('a mailed pass is 43 base64url characters');
  return pass;
}

/** The registry: one entry per template, each fixed. */
export const ENGINE_MAIL_TEMPLATES: {
  readonly [Name in EngineMailName]: EngineMailTemplate<Name>;
} = Object.freeze({
  code: Object.freeze({
    realmMaySwitchOff: false,
    carriesPass: false,
    carriesCode: () => true,
    subject: (mail: MailOf<'code'>) => codeEmailSubject(mail.purpose),
    element: (mail: MailOf<'code'>, { baseUrl, brand }: EngineMailContext) => {
      const lengths = CODE_LENGTHS[mail.purpose];
      if (lengths === undefined) throw new EngineMailError('not a code purpose');
      return createElement(CodeEmail, {
        brand,
        baseUrl,
        purpose: mail.purpose,
        code: checkCode(mail.code, lengths),
        expiresIn: checkLifetime(mail.expiresInSeconds, CODE_MAX_EXPIRES_IN_SECONDS, 'a code'),
      });
    },
  }),
  account_exists: Object.freeze({
    realmMaySwitchOff: false,
    carriesPass: false,
    carriesCode: (mail: MailOf<'account_exists'>) => mail.code !== undefined,
    subject: () => ENGINE_ACCOUNT_EXISTS_SUBJECT,
    element: (mail: MailOf<'account_exists'>, { baseUrl, brand }: EngineMailContext) => {
      if (mail.code === undefined) {
        if (mail.expiresInSeconds !== undefined) {
          throw new EngineMailError('a lifetime without a code');
        }
        return createElement(EngineAccountExistsEmail, { brand, baseUrl });
      }
      return createElement(EngineAccountExistsEmail, {
        brand,
        baseUrl,
        // The registration's code: 8 digits (ADR-017 Decision 8).
        code: checkCode(mail.code, [8]),
        expiresIn: checkLifetime(mail.expiresInSeconds, CODE_MAX_EXPIRES_IN_SECONDS, 'a code'),
      });
    },
  }),
  password_changed: Object.freeze({
    realmMaySwitchOff: false,
    carriesPass: false,
    carriesCode: () => false,
    subject: () => PASSWORD_CHANGED_SUBJECT,
    element: (_mail: MailOf<'password_changed'>, { baseUrl, brand }: EngineMailContext) =>
      createElement(PasswordChangedEmail, { brand, baseUrl }),
  }),
  password_disabled: Object.freeze({
    realmMaySwitchOff: false,
    carriesPass: true,
    carriesCode: () => false,
    subject: () => PASSWORD_DISABLED_SUBJECT,
    element: (mail: MailOf<'password_disabled'>, { baseUrl, brand }: EngineMailContext) =>
      createElement(PasswordDisabledEmail, {
        brand,
        baseUrl,
        passUrl: mailPassUrl(baseUrl, checkPass(mail.pass)),
        expiresIn: checkLifetime(mail.passExpiresInSeconds, PASS_MAX_EXPIRES_IN_SECONDS, 'a pass'),
      }),
  }),
  recovery_code_used: Object.freeze({
    realmMaySwitchOff: false,
    carriesPass: false,
    carriesCode: () => false,
    subject: () => RECOVERY_CODE_USED_SUBJECT,
    element: (mail: MailOf<'recovery_code_used'>, { baseUrl, brand }: EngineMailContext) =>
      createElement(RecoveryCodeUsedEmail, {
        brand,
        baseUrl,
        unusedCodes: checkUnusedCodes(mail.unusedCodes),
      }),
  }),
  recovery_codes_regenerated: Object.freeze({
    realmMaySwitchOff: false,
    carriesPass: false,
    carriesCode: () => false,
    subject: () => RECOVERY_CODES_REGENERATED_SUBJECT,
    element: (_mail: MailOf<'recovery_codes_regenerated'>, { baseUrl, brand }: EngineMailContext) =>
      createElement(RecoveryCodesRegeneratedEmail, { brand, baseUrl }),
  }),
  recovery_codes_failed: Object.freeze({
    realmMaySwitchOff: false,
    carriesPass: false,
    carriesCode: () => false,
    subject: () => RECOVERY_CODES_FAILED_SUBJECT,
    element: (_mail: MailOf<'recovery_codes_failed'>, { baseUrl, brand }: EngineMailContext) =>
      createElement(RecoveryCodesFailedEmail, { brand, baseUrl }),
  }),
  passkey_added: Object.freeze({
    realmMaySwitchOff: false,
    carriesPass: false,
    carriesCode: () => false,
    subject: () => PASSKEY_ADDED_SUBJECT,
    element: (_mail: MailOf<'passkey_added'>, { baseUrl, brand }: EngineMailContext) =>
      createElement(PasskeyAddedEmail, { brand, baseUrl }),
  }),
  send_ceiling: Object.freeze({
    realmMaySwitchOff: false,
    carriesPass: true,
    carriesCode: () => false,
    subject: () => SEND_CEILING_SUBJECT,
    element: (mail: MailOf<'send_ceiling'>, { baseUrl, brand }: EngineMailContext) => {
      if (mail.flow !== 'reset' && mail.flow !== 'register') {
        throw new EngineMailError('a pass starts a reset or a registration');
      }
      return createElement(SendCeilingEmail, {
        brand,
        baseUrl,
        flow: mail.flow,
        passUrl: mailPassUrl(baseUrl, checkPass(mail.pass)),
        expiresIn: checkLifetime(mail.passExpiresInSeconds, PASS_MAX_EXPIRES_IN_SECONDS, 'a pass'),
      });
    },
  }),
});

/** Every template's name, in the registry's order. */
export const ENGINE_MAIL_NAMES = Object.freeze(
  Object.keys(ENGINE_MAIL_TEMPLATES) as EngineMailName[]
);

/** The registry entry of `mail`'s template, typed for its data. */
function templateOf<Name extends EngineMailName>(mail: MailOf<Name>): EngineMailTemplate<Name> {
  const template = (
    ENGINE_MAIL_TEMPLATES as unknown as Record<string, EngineMailTemplate<Name> | undefined>
  )[mail.template];
  if (template === undefined) throw new EngineMailError('not an engine mail template');
  return template;
}

/**
 * Whether `mail` carries a code, and so counts toward the send caps and may be
 * dropped at the quiet one. A mail with no code is never counted and never
 * suppressed (ADR-017 Decision 5).
 */
export function engineMailCarriesCode(mail: EngineMail): boolean {
  return templateOf(mail as MailOf<EngineMailName>).carriesCode(mail as never);
}

/**
 * Whether a realm that switched `name` off keeps it from being sent. A realm
 * may switch off only a template the registry lets it; every other template
 * goes out whatever the realm says, the send-ceiling and password-disabled
 * notices among them (ADR-017 Decision 7, ADR-020 §3 "Emails").
 *
 * @param switchedOff - the templates the realm's notice settings switch off
 */
export function isSwitchedOffByRealm(
  name: EngineMailName,
  switchedOff: ReadonlySet<string>
): boolean {
  const template = (ENGINE_MAIL_TEMPLATES as Record<string, { realmMaySwitchOff: boolean }>)[name];
  return template !== undefined && template.realmMaySwitchOff && switchedOff.has(name);
}

/**
 * Render `mail` for the realm `context` describes: its subject, HTML and
 * plain text.
 *
 * @throws EngineMailError when the data does not fit the template, or the
 *   context's base URL is not a realm issuer
 */
export async function renderEngineMail(
  mail: EngineMail,
  context: EngineMailContext
): Promise<RenderedEngineMail> {
  if (!isMailBaseUrl(context.baseUrl)) {
    throw new EngineMailError('a mail links to the realm issuer');
  }
  const template = templateOf(mail as MailOf<EngineMailName>);
  const element = template.element(mail as never, context);
  const [html, text] = await Promise.all([renderEmail(element), renderEmailText(element)]);
  return { subject: template.subject(mail as never), html, text };
}
