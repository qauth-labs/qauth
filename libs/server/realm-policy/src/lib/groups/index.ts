import { ACCOUNTS_POLICY_GROUP } from './accounts';
import { ADMIN_POLICY_GROUP } from './admin';
import { BRUTE_FORCE_POLICY_GROUP } from './brute-force';
import { MAIL_POLICY_GROUP, mailTransportGaps, mailTransportIssues } from './mail';
import { PASSWORD_POLICY_GROUP } from './password';
import { POSTURE_POLICY_GROUP } from './posture';
import { REGISTRATION_POLICY_GROUP } from './registration';
import { TOKENS_POLICY_GROUP } from './tokens';

export {
  ACCOUNTS_POLICY_GROUP,
  ADMIN_POLICY_GROUP,
  BRUTE_FORCE_POLICY_GROUP,
  MAIL_POLICY_GROUP,
  mailTransportGaps,
  mailTransportIssues,
  PASSWORD_POLICY_GROUP,
  POSTURE_POLICY_GROUP,
  REGISTRATION_POLICY_GROUP,
  TOKENS_POLICY_GROUP,
};

/**
 * The groups this library defines (#514), by name, in the order they are
 * registered and listed. Other areas register theirs on the same registry
 * (sessions, sign-in methods, MFA, brand, upstream providers, event
 * retention).
 */
export const BUILT_IN_POLICY_GROUPS = Object.freeze({
  tokens: TOKENS_POLICY_GROUP,
  accounts: ACCOUNTS_POLICY_GROUP,
  password: PASSWORD_POLICY_GROUP,
  bruteForce: BRUTE_FORCE_POLICY_GROUP,
  registration: REGISTRATION_POLICY_GROUP,
  mail: MAIL_POLICY_GROUP,
  posture: POSTURE_POLICY_GROUP,
  admin: ADMIN_POLICY_GROUP,
} as const);
