import { createHash, randomBytes } from 'node:crypto';

import {
  checkSendCapPolicy,
  type MailPassBinding,
  type MailPassFlow,
  type OnceANoticeKind,
  SEND_CAP_POLICY,
  type SendCapDecision,
  type SendCapPolicy,
  type SendCapRefusingTier,
  type SendCapRequest,
  type SendCapStore,
  type SendWindow,
} from '../lib/send-caps';

/**
 * TEST SUPPORT — the send caps in memory, on a clock the test moves: the
 * rules of {@link SendCapPolicy} as the auth server's Redis script applies
 * them (`@qauth-labs/fastify-plugin-sign-in-engine`'s `send-caps.ts`). Not for
 * production: nothing is shared between processes.
 */
export interface MemorySendCaps extends SendCapStore {
  /** Every decision, in order. */
  readonly decisions: SendCapDecision[];
  /** The passes kept, by realm and hash (`<realm id>:<pass hash>`). */
  passes(): ReadonlyMap<string, MailPassBinding & { readonly expiresAt: number }>;
}

/** The SHA-256 of a pass, base64url: the key the store keeps its binding under. */
export function mailPassHash(pass: string): string {
  return createHash('sha256').update(pass).digest('base64url');
}

/** Send caps in memory over `now`, with `policy` ({@link SEND_CAP_POLICY} by default). */
export function createMemorySendCaps(
  now: () => number,
  policy: SendCapPolicy = SEND_CAP_POLICY
): MemorySendCaps {
  checkSendCapPolicy(policy);
  /** Each log's send times, ascending. */
  const logs = new Map<string, number[]>();
  const passes = new Map<string, MailPassBinding & { expiresAt: number }>();
  const marks = new Map<string, number>();
  const decisions: SendCapDecision[] = [];

  const log = (key: string, keepMs: number, at: number): number[] => {
    const kept = (logs.get(key) ?? []).filter((time) => time > at - keepMs);
    logs.set(key, kept);
    return kept;
  };
  const within = (times: readonly number[], window: SendWindow, at: number) =>
    times.filter((time) => time > at - window.windowMs);
  const retry = (times: readonly number[], window: SendWindow, at: number) => {
    const inWindow = within(times, window, at);
    const leaving = inWindow[inWindow.length - window.limit];
    return Math.max(1, leaving + window.windowMs - at);
  };
  /** Claim a mark for `ttl`: `true` when none was live. */
  const claim = (key: string, ttl: number, at: number) => {
    const until = marks.get(key);
    if (until !== undefined && until > at) return false;
    marks.set(key, at + ttl);
    return true;
  };

  const decide = (request: SendCapRequest, at: number): SendCapDecision => {
    const { realmId, addressHmac: address, endUserIpHmac: ip, clientKey: client } = request;
    const key = (...parts: string[]) => [realmId, ...parts].join(':');
    const refused = (
      tier: SendCapRefusingTier,
      times: readonly number[],
      window: SendWindow,
      alert = false
    ): SendCapDecision => ({
      kind: 'refused',
      tier,
      retryAfterMs: retry(times, window, at),
      alert,
    });

    const ipLog = ip === undefined ? undefined : log(key('ip', ip), policy.endUserIp.windowMs, at);
    if (ipLog !== undefined && ipLog.length >= policy.endUserIp.limit) {
      return refused('end_user_ip', ipLog, policy.endUserIp);
    }
    const clientLog =
      client === undefined ? undefined : log(key('client', client), policy.client.windowMs, at);
    if (clientLog !== undefined && clientLog.length >= policy.client.limit) {
      return refused('client', clientLog, policy.client);
    }

    const passKey = request.passHash === undefined ? undefined : `${realmId}:${request.passHash}`;
    const pass = passKey === undefined ? undefined : passes.get(passKey);
    const passOk = pass !== undefined && pass.expiresAt > at && pass.addressHmac === address;
    const exempt = request.knownIp || passOk;

    const ceilingKey = key(request.afterFirstFactor ? 'after-first-factor' : 'ceiling', address);
    const ceilingWindow = request.afterFirstFactor ? policy.afterFirstFactor : policy.ceiling;
    const addressClientKey =
      client === undefined ? undefined : key('address-client', address, client);
    const addressIpKey = ip === undefined ? undefined : key('address-ip', address, ip);
    if (!exempt) {
      const ceilingLog = log(ceilingKey, ceilingWindow.windowMs, at);
      if (ceilingLog.length >= ceilingWindow.limit) {
        if (request.afterFirstFactor) {
          return refused('after_first_factor', ceilingLog, ceilingWindow);
        }
        const alert = claim(key('alert', address), policy.noticeIntervalMs, at);
        return refused('ceiling', ceilingLog, ceilingWindow, alert);
      }
      if (addressClientKey !== undefined) {
        const times = log(addressClientKey, policy.addressClient.windowMs, at);
        if (times.length >= policy.addressClient.limit) {
          return refused('address_client', times, policy.addressClient);
        }
      }
      if (addressIpKey !== undefined) {
        const times = log(addressIpKey, policy.addressIpLong.windowMs, at);
        if (
          within(times, policy.addressIpShort, at).length >= policy.addressIpShort.limit ||
          times.length >= policy.addressIpLong.limit
        ) {
          return { kind: 'quiet' };
        }
      }
    }

    ipLog?.push(at);
    clientLog?.push(at);
    if (!exempt) {
      logs.get(ceilingKey)?.push(at);
      if (addressClientKey !== undefined) logs.get(addressClientKey)?.push(at);
      if (addressIpKey !== undefined) logs.get(addressIpKey)?.push(at);
    }
    if (passOk && passKey !== undefined) passes.delete(passKey);
    return { kind: 'send', passSpent: passOk };
  };

  return {
    decisions,
    passes: () => new Map(passes),

    async reserve(request) {
      const decision = decide(request, now());
      decisions.push(decision);
      return decision;
    },

    async mintPass(input: { realmId: string; addressHmac: string; flow: MailPassFlow }) {
      const pass = randomBytes(32).toString('base64url');
      passes.set(`${input.realmId}:${mailPassHash(pass)}`, {
        passHash: mailPassHash(pass),
        addressHmac: input.addressHmac,
        flow: input.flow,
        expiresAt: now() + policy.passTtlMs,
      });
      return pass;
    },

    async peekPass(realmId: string, pass: string) {
      const binding = passes.get(`${realmId}:${mailPassHash(pass)}`);
      if (binding === undefined || binding.expiresAt <= now()) return undefined;
      const { passHash, addressHmac, flow } = binding;
      return { passHash, addressHmac, flow };
    },

    async claimNotice(input: { realmId: string; addressHmac: string; kind: OnceANoticeKind }) {
      return claim(
        [input.realmId, 'notice', input.kind, input.addressHmac].join(':'),
        policy.noticeIntervalMs,
        now()
      );
    },
  };
}
