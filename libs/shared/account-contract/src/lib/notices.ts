/**
 * The security notices a person may receive (ADR-020 §3, Emails; #693), as the
 * account API's notification preferences list them: a closed list.
 *
 * A notice goes to the account's contact address; an account with none sees
 * it only in its security log. Most notices cannot be switched off: those
 * about credential changes, those that carry a reset pass (the send-ceiling
 * and password-disable notices, ADR-017 Decisions 5 and 7) and the notice of
 * a wrong second factor after a correct password (ADR-017 Decision 7). A
 * realm may switch off the others. The account API reads the result; who may
 * switch a notice off is the realm's setting (#693).
 */

export interface Notice {
  readonly description: string;
  /** Whether it always goes out: no realm setting switches it off. */
  readonly mandatory: boolean;
}

export const NOTICES = {
  new_device: {
    description: 'A sign-in from a device QAuth had not seen for the account.',
    mandatory: false,
  },
  password_changed: { description: 'The password was changed.', mandatory: true },
  credential_disabled: {
    description:
      'The password or the authenticator app was disabled after too many wrong attempts. It carries a reset pass.',
    mandatory: true,
  },
  credential_added: {
    description: 'A passkey or an authenticator app was added.',
    mandatory: true,
  },
  credential_removed: {
    description: 'A passkey or an authenticator app was removed.',
    mandatory: true,
  },
  recovery_code_used: { description: 'A recovery code was used.', mandatory: true },
  recovery_codes_regenerated: {
    description: 'The recovery codes were regenerated.',
    mandatory: true,
  },
  recovery_codes_failed: {
    description: 'Recovery codes were tried and refused 100 times.',
    mandatory: false,
  },
  send_ceiling_reached: {
    description: 'Codes were requested past the per-address send ceiling. It carries a reset pass.',
    mandatory: true,
  },
  second_factor_failed: {
    description: 'A wrong second factor followed a correct password.',
    mandatory: true,
  },
  identifier_changed: {
    description: 'The sign-in address or the contact address changed; sent to the old address.',
    mandatory: true,
  },
  account_deleted: { description: 'The account was deleted.', mandatory: true },
} as const satisfies Record<string, Notice>;

export type NoticeName = keyof typeof NOTICES;

export const NOTICE_NAMES = Object.keys(NOTICES) as NoticeName[];
