import {
  type EngineMail,
  engineMailCarriesCode,
  type EngineMailContext,
  type RealmEmailService,
  resolveMailBrand,
} from '@qauth-labs/fastify-plugin-email';
import {
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
} from '@qauth-labs/fastify-plugin-federation';
import {
  createRedisSendCaps,
  isKnownEndUserIp,
  type MailPassFlow,
  type PasswordDisabledNotices,
  retryAfterSeconds,
  SEND_CAP_POLICY,
  type SendCapStore,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { type BackgroundTasks, createBackgroundTasks } from './background-tasks';
import { createServerDigests, ladderEndUserIp, type ServerDigests } from './password-attempts';
import { realmMailLink } from './realm-url';
import type { RealmRow } from './request-realm';

/**
 * THE ENGINE'S MAIL AND ITS SEND CAPS (PRO-14, #637; ADR-017 Decisions 5
 * and 7, ADR-020 §3).
 *
 * The one way the sign-in engine's starts mail an address:
 *
 * - **A code** ({@link EngineMailer.sendCode}) goes through the layered send
 *   caps (`createRedisSendCaps`): per address and end-user IP (quiet: the
 *   caller answers the same step and the mail is dropped), per address and
 *   FiPA client, the per-address ceiling, the after-first-factor cap, per
 *   end-user IP and per FiPA client (each a 429 with `Retry-After`, the same
 *   for every address). Every request counts, the ones for an address with
 *   no account too (`mail` absent): the caps answer the same whatever the
 *   account. A known IP of a verified account skips every per-address tier;
 *   a code after a correct first factor skips the ceiling and counts toward
 *   its own cap. The pass a mailed notice carries (its hash, from the
 *   interaction) takes one start past every per-address tier and is spent by
 *   it, never by opening its link.
 * - **Mail with no code** ({@link EngineMailer.sendUncounted}) is not counted
 *   and never suppressed.
 * - **The notices that carry a pass**: the send-ceiling notice, at most one
 *   per account per 24 hours (and, on a registration start, one per address
 *   with no account), and the password-disabled notice of the failure
 *   ladder's hard action ({@link EngineMailer.passwordDisabledNotices}). A
 *   realm cannot switch either off: nothing here asks it.
 *
 * Every mail is dispatched after the caller's answer is built
 * (`createBackgroundTasks`): "sent", "not sent" and "capped quietly" take the
 * same time and give the same answer, and the caller holds the round to its
 * timing floor. Every link starts at the realm's issuer (`realmMailLink`).
 *
 * At the ceiling the operator is alerted, once per address HMAC per 24 hours
 * ({@link SEND_CEILING_ALERT}): the log line names the realm and the HMAC,
 * never the address.
 */

/** The message of the operator's alert when an address meets the send ceiling. */
export const SEND_CEILING_ALERT = 'an address met the per-address send ceiling';

/** How long a mailed pass is good for, in seconds: what the notice says. */
const PASS_TTL_SECONDS = Math.floor(SEND_CAP_POLICY.passTtlMs / 1000);

/** The realm a mail is sent in: its id, and its issuer, which every link starts at. */
export type MailRealm = Pick<RealmRow, 'id' | 'issuer'>;

/** A mail that carries a code: the only mail the send caps count. */
export type CodeMail = Extract<EngineMail, { readonly template: 'code' | 'account_exists' }>;

/** What a start asks to mail. */
export interface CappedSendInput {
  readonly realm: MailRealm;
  /** The normalised address: the identifier the account and its caps are keyed on. */
  readonly address: string;
  /**
   * The mail, for an address that gets one. Absent for one that gets none (an
   * unknown address at a reset start): the request still counts, so the
   * caps answer it as they answer any other address.
   */
  readonly mail?: CodeMail;
  /** The start that asked: what a send-ceiling notice's pass opens. */
  readonly flow: MailPassFlow;
  /** The FiPA client the request came through; absent on the hosted pages, which have no per-client tier. */
  readonly fipaClientId?: string;
  /** Whether a correct first factor came before, in the same transaction. */
  readonly afterFirstFactor?: boolean;
  /** The hash of the mailed pass the interaction carries (`mailPassHash`). */
  readonly passHash?: string;
  /**
   * The end-user IP, when it is not the request's client address (a FiPA
   * assertion's). Absent, it is the request's (`ladderEndUserIp`).
   */
  readonly endUserIp?: string;
}

/** What {@link EngineMailer.sendCode} decided. */
export type CappedSendOutcome =
  /**
   * Answer the same step: the mail went out, or was quietly dropped, or the
   * address gets none. The caller cannot tell which, and must not try.
   * `passSpent`: the start used the pass, which no other start can use now.
   */
  | { readonly kind: 'accepted'; readonly passSpent: boolean }
  /** Answer 429 `temporarily_unavailable` with this `Retry-After`, whatever the address. */
  | { readonly kind: 'capped'; readonly retryAfterSeconds: number };

/** The engine's mail of a process. */
export interface EngineMailer {
  /** Count and, unless a tier stops it, mail a code. Rejects when a store fails: fail closed. */
  sendCode(request: FastifyRequest, input: CappedSendInput): Promise<CappedSendOutcome>;
  /** Mail with no code: not counted, never suppressed, dispatched after the answer. */
  sendUncounted(realm: MailRealm, address: string, mail: EngineMail): void;
  /** The failure ladder's password-disabled notice (#615), with its pass. */
  readonly passwordDisabledNotices: PasswordDisabledNotices;
}

/** A password account as the caps read it. */
export interface MailAccount {
  readonly enabled: boolean;
  /** Whether its address is verified. */
  readonly verified: boolean;
}

/** What {@link createCappedMailer} works with. */
export interface CappedMailerDependencies {
  readonly caps: SendCapStore;
  readonly digests: ServerDigests;
  /** Whether a successful sign-in of the identifier came from the IP lately (the ladder's known IPs). */
  readonly isKnownIp: (query: {
    readonly realmId: string;
    readonly identifierHmac: string;
    readonly endUserIpHmac: string;
  }) => Promise<boolean>;
  /** The password account the address names in the realm, if any. */
  readonly accountOf: (realmId: string, address: string) => Promise<MailAccount | undefined>;
  /** The realm of a notice sent outside a request. */
  readonly realmOf: (realmId: string) => Promise<MailRealm | undefined>;
  readonly mail: Pick<RealmEmailService, 'sendEngineMail' | 'canSend'>;
  readonly tasks: BackgroundTasks;
  readonly log: { error(details: Record<string, unknown>, message: string): void };
  /**
   * Whether a realm on the mock transport counts as able to send the
   * password-disabled notice: outside production only, where a mock is how
   * a deployment tests its mail.
   */
  readonly mockSends: boolean;
}

/** Where a realm's mail links point, and how it looks. */
function contextOf(realm: MailRealm): EngineMailContext {
  // No brand settings exist yet: every realm's mail has the default look.
  return { ...realmMailLink(realm), brand: resolveMailBrand(undefined) };
}

/** The engine's mail over explicit dependencies; {@link createEngineMailer} wires the process's. */
export function createCappedMailer(deps: CappedMailerDependencies): EngineMailer {
  const send = (realm: MailRealm, address: string, mail: EngineMail) =>
    deps.mail.sendEngineMail(realm.id, address, mail, contextOf(realm));

  /** A known IP of a verified, enabled account: the exemption from every per-address tier. */
  async function knownIpOfVerifiedAccount(
    realmId: string,
    address: string,
    identifierHmac: string,
    endUserIpHmac: string
  ): Promise<boolean> {
    if (!(await deps.isKnownIp({ realmId, identifierHmac, endUserIpHmac }))) return false;
    const account = await deps.accountOf(realmId, address);
    return account !== undefined && account.enabled && account.verified;
  }

  /**
   * The send-ceiling notice, outside the caps: to an enabled account, with a
   * pass for a reset, or, on a registration start, to an address with no
   * account, with a pass for a registration. Claimed only when it has a
   * recipient, so a start that cannot send one does not use up the day's.
   */
  async function ceilingNotice(
    realm: MailRealm,
    address: string,
    addressHmac: string,
    flow: MailPassFlow
  ): Promise<void> {
    const account = await deps.accountOf(realm.id, address);
    let passFlow: MailPassFlow;
    if (account !== undefined) {
      if (!account.enabled) return;
      passFlow = 'reset';
    } else if (flow === 'register') {
      passFlow = 'register';
    } else {
      return;
    }
    const realmId = realm.id;
    if (!(await deps.caps.claimNotice({ realmId, addressHmac, kind: 'send_ceiling' }))) return;
    const pass = await deps.caps.mintPass({ realmId, addressHmac, flow: passFlow });
    await send(realm, address, {
      template: 'send_ceiling',
      flow: passFlow,
      pass,
      passExpiresInSeconds: PASS_TTL_SECONDS,
    });
  }

  return Object.freeze({
    async sendCode(request: FastifyRequest, input: CappedSendInput): Promise<CappedSendOutcome> {
      const { realm, address, mail } = input;
      if (mail !== undefined && !engineMailCarriesCode(mail)) {
        throw new Error('engine mail: only a mail that carries a code goes through the send caps');
      }
      const realmId = realm.id;
      const addressHmac = await deps.digests.identifierDigest({ realmId, identifier: address });
      const endUserIp = input.endUserIp ?? ladderEndUserIp(request).endUserIp;
      const endUserIpHmac =
        endUserIp === undefined || endUserIp === ''
          ? undefined
          : await deps.digests.ipDigest({ realmId, identifier: endUserIp });
      const knownIp =
        endUserIpHmac !== undefined &&
        (await knownIpOfVerifiedAccount(realmId, address, addressHmac, endUserIpHmac));

      const decision = await deps.caps.reserve({
        realmId,
        addressHmac,
        ...(endUserIpHmac === undefined ? {} : { endUserIpHmac }),
        ...(input.fipaClientId === undefined ? {} : { clientKey: input.fipaClientId }),
        knownIp,
        afterFirstFactor: input.afterFirstFactor === true,
        ...(input.passHash === undefined ? {} : { passHash: input.passHash }),
      });

      if (decision.kind === 'refused') {
        if (decision.tier === 'ceiling') {
          // The operator's alert: this log line is the alerting hook.
          if (decision.alert) deps.log.error({ realmId, addressHmac }, SEND_CEILING_ALERT);
          deps.tasks.run(
            () => ceilingNotice(realm, address, addressHmac, input.flow),
            'the send-ceiling notice was not sent'
          );
        }
        return { kind: 'capped', retryAfterSeconds: retryAfterSeconds(decision.retryAfterMs) };
      }
      if (decision.kind === 'send' && mail !== undefined) {
        deps.tasks.run(() => send(realm, address, mail), 'a mailed code was not sent');
      }
      return { kind: 'accepted', passSpent: decision.kind === 'send' && decision.passSpent };
    },

    sendUncounted(realm: MailRealm, address: string, mail: EngineMail): void {
      if (engineMailCarriesCode(mail)) {
        throw new Error('engine mail: a mail that carries a code goes through the send caps');
      }
      deps.tasks.run(() => send(realm, address, mail), 'an engine mail was not sent');
    },

    passwordDisabledNotices: Object.freeze({
      canSend: (realmId: string) => deps.mail.canSend(realmId, { mockSends: deps.mockSends }),
      async passwordDisabled({ realmId, identifier }: { realmId: string; identifier: string }) {
        const realm = await deps.realmOf(realmId);
        if (realm === undefined) throw new Error('the realm of a disabled password is gone');
        const addressHmac = await deps.digests.identifierDigest({ realmId, identifier });
        if (!(await deps.caps.claimNotice({ realmId, addressHmac, kind: 'password_disabled' }))) {
          return;
        }
        const pass = await deps.caps.mintPass({ realmId, addressHmac, flow: 'reset' });
        await send(realm, identifier, {
          template: 'password_disabled',
          pass,
          passExpiresInSeconds: PASS_TTL_SECONDS,
        });
      },
    }),
  });
}

/**
 * The engine's mail of this process: the send caps over its Redis, the
 * ladder's digests and known IPs, its `user_credentials`, `users` and
 * `realms`, and the mail service of every realm. The mail service is read
 * when a mail goes out, so a process may build this before the email plugin
 * registers; every process that holds the failure ladder registers it
 * (`service-roles.ts`).
 */
export function createEngineMailer(fastify: FastifyInstance): EngineMailer {
  return createCappedMailer({
    caps: createRedisSendCaps(fastify.redis),
    digests: createServerDigests(fastify),
    isKnownIp: (query) => isKnownEndUserIp(fastify.redis, query),
    async accountOf(realmId, address) {
      const credential = await fastify.repositories.userCredentials.findByRealmProviderSub(
        realmId,
        PASSWORD_PROVIDER_TYPE,
        address
      );
      if (!credential) return undefined;
      const user = await fastify.repositories.users.findById(realmId, credential.userId);
      if (!user) return undefined;
      const data = passwordCredentialDataSchema.safeParse(credential.credentialData);
      return { enabled: user.enabled, verified: data.success && data.data.email_verified };
    },
    realmOf: (realmId) => fastify.repositories.realms.findById(realmId),
    mail: {
      sendEngineMail: (...args) => fastify.emailService.sendEngineMail(...args),
      canSend: (...args) => fastify.emailService.canSend(...args),
    },
    tasks: createBackgroundTasks(fastify),
    log: fastify.log,
    mockSends: env.NODE_ENV !== 'production',
  });
}
