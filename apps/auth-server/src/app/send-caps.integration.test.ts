import { createHash } from 'node:crypto';

import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE ENGINE MAIL AND ITS SEND CAPS ON A REAL REDIS AND POSTGRES (#637,
 * ADR-017 Decisions 5 and 7).
 *
 * Each test boots the real auth server, empties its state and drives a
 * stand-in start route that mails a recovery code the way the reset and
 * registration starts will (#642, #644): it mails a code only to an address
 * with a password account, sends every request through the engine mailer
 * (`helpers/engine-mail.ts`), holds the answer to the sign-in timing floor,
 * and answers a capped request with 429 and `Retry-After`. The mailed pass
 * link is opened through the real `GET /auth/pass`.
 *
 * It proves the issue's integration criteria: "sent", "quietly dropped" and
 * "not sent" give one body at one timing floor; at the ceiling an existing
 * and an unknown address get the same 429; the ceiling alerts the operator
 * and sends at most one notice per account a day; the pass is single use,
 * bound to its address, valid 24 hours and not spent by opening its link; a
 * known IP of a verified account meets no per-address tier; and a third party
 * who spends an address's tiers from other IPs cannot stop the owner's reset.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const OWNER = 'owner@example.com';
const UNKNOWN = 'nobody@example.com';
const DAY_MS = 24 * 60 * 60 * 1000;
/** `SEND_CEILING_ALERT`, written out: importing it would load the env module first. */
const SEND_CEILING_ALERT = 'an address met the per-address send ceiling';
/** `MIN_RESPONSE_TIME_MS.LOGIN`, the floor of every identifier-resolving round. */
const TIMING_FLOOR_MS = 500;

/**
 * A pass's hash as the store and the interaction keep it (`mailPassHash`),
 * written out: a dynamic import of the sign-in engine plugin here would make
 * it a lazy-loaded library for every static import of the app.
 */
const mailPassHash = (pass: string) => createHash('sha256').update(pass).digest('base64url');

/** What the stand-in start route takes. */
interface SendCodeBody {
  readonly address: string;
  readonly flow?: 'reset' | 'register';
  readonly passHash?: string;
  /** `false` for the requests a test only spends a tier with. */
  readonly floor?: boolean;
}

/** One mail the engine mailer handed the realm's mail service. */
interface SentMail {
  readonly to: string;
  readonly mail: EngineMail;
  readonly baseUrl: string;
}

/** The stand-in start route, over the app's own engine mailer. */
async function sendCapRoutes(app: FastifyInstance): Promise<void> {
  // Imported here, after the boot reset the module registry, so these are the
  // instances the app loaded.
  const { createEngineMailer } = await import('./helpers/engine-mail');
  const { requestRealm } = await import('./helpers/request-realm');
  const { ensureMinimumResponseTime } = await import('./helpers/timing');
  const mailer = createEngineMailer(app);

  app.post('/test/send-code', { config: { surface: 'browser' } }, async (request, reply) => {
    const startedAt = Date.now();
    const body = request.body as SendCodeBody;
    const realm = requestRealm(request);
    const address = body.address.toLowerCase();
    const credential = await app.repositories.userCredentials.findByRealmProviderSub(
      realm.id,
      'password',
      address
    );
    const outcome = await mailer.sendCode(request, {
      realm,
      address,
      ...(credential
        ? {
            mail: {
              template: 'code',
              purpose: 'recovery',
              code: '12345678',
              expiresInSeconds: 600,
            } as const,
          }
        : {}),
      flow: body.flow ?? 'reset',
      ...(body.passHash === undefined ? {} : { passHash: body.passHash }),
    });
    if (body.floor !== false) await ensureMinimumResponseTime(startedAt, TIMING_FLOOR_MS);
    if (outcome.kind === 'capped') {
      return reply
        .code(429)
        .header('Retry-After', String(outcome.retryAfterSeconds))
        .send({ code: 'temporarily_unavailable' });
    }
    return { step: 'email_code' };
  });
}

describe('the engine mail and its send caps (#637, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];
  const logLines: string[] = [];
  const sent: SentMail[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
    logLines.length = 0;
    sent.length = 0;
  });

  afterEach(async () => {
    vi.useRealTimers();
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  async function boot(): Promise<FastifyInstance> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const server = await bootAuthServer(baseEnvironment(infra, jwt), {
      routes: sendCapRoutes,
      logStream: { write: (line) => void logLines.push(line) },
    });
    booted.push(server);
    await resetE2eState(server.app);
    const { emailService } = server.app;
    const original = emailService.sendEngineMail.bind(emailService);
    emailService.sendEngineMail = async (realmId, to, mail, context) => {
      sent.push({ to, mail, baseUrl: context.baseUrl });
      return original(realmId, to, mail, context);
    };
    return server.app;
  }

  function sendCode(
    app: FastifyInstance,
    ip: string,
    body: SendCodeBody
  ): Promise<LightMyRequestResponse> {
    return app.inject({ method: 'POST', url: '/test/send-code', remoteAddress: ip, payload: body });
  }

  /** Spend `count` sends of `address` from as many IPs, none of them `127.0.0.1`. */
  async function spend(app: FastifyInstance, address: string, count: number, net = 100) {
    for (let i = 1; i <= count; i++) {
      const response = await sendCode(app, `198.51.${net}.${i}`, { address, floor: false });
      expect(response.statusCode, response.body).toBe(200);
    }
  }

  /** The mails of `template` sent to `to` so far. */
  const mailsTo = (to: string, template: EngineMail['template']) =>
    sent.filter((entry) => entry.to === to && entry.mail.template === template);

  /** Wait until `count` mails of `template` went to `to`, then a moment for any more. */
  async function settle(to: string, template: EngineMail['template'], count: number) {
    const deadline = Date.now() + 5_000;
    while (mailsTo(to, template).length < count && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
    return mailsTo(to, template);
  }

  /** The pass the last send-ceiling notice to `to` carried. */
  async function noticedPass(to: string): Promise<string> {
    const [notice] = await settle(to, 'send_ceiling', 1);
    if (notice?.mail.template !== 'send_ceiling') throw new Error(`no notice went to ${to}`);
    return notice.mail.pass;
  }

  /** Open a pass link; the interaction's id when it redirects. */
  async function openPass(app: FastifyInstance, pass: string) {
    const response = await app.inject({ method: 'GET', url: `/auth/pass?pass=${pass}` });
    const id = /^\/ui\/interaction\/([A-Za-z0-9_-]{43})$/.exec(
      String(response.headers.location ?? '')
    )?.[1];
    return { response, id };
  }

  /** The pass hash the interaction `id` holds. */
  async function passHashOf(app: FastifyInstance, id: string): Promise<string | undefined> {
    const { interactionIdHash, readInteractionRecord } =
      await import('./helpers/interaction-record');
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('no realm');
    const record = await readInteractionRecord(app.redis, app.log, realm.id, interactionIdHash(id));
    return record?.purpose === 'mailed_pass' ? record.request.passHash : undefined;
  }

  const alerts = () =>
    logLines
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((line) => line['msg'] === SEND_CEILING_ALERT);

  it('gives "sent", "quietly dropped" and "not sent" one body at one timing floor', async () => {
    const app = await boot();
    await registerPasswordAccount(app, OWNER);

    const timed = async (ip: string, address: string) => {
      const before = Date.now();
      const response = await sendCode(app, ip, { address });
      return { response, elapsed: Date.now() - before };
    };
    const answers = [
      ...(await Promise.all([1, 2, 3].map(() => timed('203.0.113.1', OWNER)))),
      // The fourth from the same IP in 15 minutes: quietly dropped.
      await timed('203.0.113.1', OWNER),
      // No account: nothing to send, counted all the same.
      await timed('203.0.113.2', UNKNOWN),
    ];

    for (const { response, elapsed } of answers) {
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe(answers[0]?.response.body);
      expect(elapsed).toBeGreaterThanOrEqual(TIMING_FLOOR_MS);
    }
    expect(await settle(OWNER, 'code', 3)).toHaveLength(3);
    expect(mailsTo(UNKNOWN, 'code')).toHaveLength(0);
  }, 120_000);

  it('answers an existing and an unknown address at the ceiling with the same 429, alerts once and notices once', async () => {
    const app = await boot();
    await registerPasswordAccount(app, OWNER);
    await spend(app, OWNER, 30, 100);
    await spend(app, UNKNOWN, 30, 101);

    const owner = await sendCode(app, '203.0.113.10', { address: OWNER });
    const unknown = await sendCode(app, '203.0.113.11', { address: UNKNOWN });
    for (const response of [owner, unknown]) {
      expect(response.statusCode).toBe(429);
      expect(Number(response.headers['retry-after'])).toBeGreaterThan(DAY_MS / 1000 - 120);
    }
    expect(owner.body).toBe(unknown.body);

    // Two more refusals: still one alert per address, and one notice.
    expect((await sendCode(app, '203.0.113.12', { address: OWNER })).statusCode).toBe(429);
    expect((await sendCode(app, '203.0.113.13', { address: UNKNOWN })).statusCode).toBe(429);
    const notices = await settle(OWNER, 'send_ceiling', 1);
    expect(notices).toHaveLength(1);
    expect(notices[0]?.mail).toMatchObject({ template: 'send_ceiling', flow: 'reset' });
    expect(notices[0]?.baseUrl).toBe('https://auth.example.com');
    // A reset start for an address with no account sends no notice.
    expect(mailsTo(UNKNOWN, 'send_ceiling')).toHaveLength(0);
    // No code past the ceiling.
    expect(mailsTo(OWNER, 'code')).toHaveLength(30);

    const alerted = alerts();
    expect(alerted).toHaveLength(2);
    expect(new Set(alerted.map((line) => line['addressHmac'])).size).toBe(2);
    expect(JSON.stringify(alerted)).not.toContain(OWNER);
    expect(JSON.stringify(alerted)).not.toContain(UNKNOWN);

    // On a registration start the address with no account gets its notice.
    expect(
      (await sendCode(app, '203.0.113.14', { address: UNKNOWN, flow: 'register' })).statusCode
    ).toBe(429);
    const registration = await settle(UNKNOWN, 'send_ceiling', 1);
    expect(registration).toHaveLength(1);
    expect(registration[0]?.mail).toMatchObject({ flow: 'register' });
  }, 120_000);

  it('takes one start past the ceiling with the pass, bound to its address, never spent by its link, for 24 hours', async () => {
    const app = await boot();
    await registerPasswordAccount(app, OWNER);
    await spend(app, OWNER, 30, 100);
    await spend(app, UNKNOWN, 30, 101);
    expect((await sendCode(app, '203.0.113.20', { address: OWNER })).statusCode).toBe(429);
    const pass = await noticedPass(OWNER);

    // Valid 24 hours: a day later the link opens nothing; until then it does.
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + DAY_MS });
    expect((await openPass(app, pass)).response.statusCode).toBe(400);
    vi.useRealTimers();

    // Opening the link twice opens two interactions, and spends nothing.
    const first = await openPass(app, pass);
    const second = await openPass(app, pass);
    for (const opened of [first, second]) {
      expect(opened.response.statusCode).toBe(303);
      expect(opened.id).toBeDefined();
      expect(String(opened.response.headers['set-cookie'])).toContain('__Host-qauth_flow=');
    }
    const passHash = await passHashOf(app, first.id as string);
    expect(passHash).toBe(mailPassHash(pass));
    expect(await passHashOf(app, second.id as string)).toBe(passHash);

    // Bound to its address: another address at its ceiling is still refused.
    expect((await sendCode(app, '203.0.113.21', { address: UNKNOWN, passHash })).statusCode).toBe(
      429
    );
    // The owner's start goes through, and the code is mailed.
    const before = mailsTo(OWNER, 'code').length;
    expect((await sendCode(app, '203.0.113.22', { address: OWNER, passHash })).statusCode).toBe(
      200
    );
    expect(await settle(OWNER, 'code', before + 1)).toHaveLength(before + 1);
    // Single use: the second start with it meets the ceiling, and its link opens nothing.
    expect((await sendCode(app, '203.0.113.23', { address: OWNER, passHash })).statusCode).toBe(
      429
    );
    expect((await openPass(app, pass)).response.statusCode).toBe(400);
  }, 120_000);

  it('lets a known IP of a verified account past every per-address tier, and no other IP', async () => {
    const app = await boot();
    await registerPasswordAccount(app, OWNER);
    // A successful sign-in from 127.0.0.1, the inject's own address, makes it known.
    await signInWithPassword(app, OWNER);

    for (let i = 0; i < 5; i++) {
      expect((await sendCode(app, '127.0.0.1', { address: OWNER, floor: false })).statusCode).toBe(
        200
      );
    }
    // Past the quiet 3 per 15 minutes of an address and an IP.
    expect(await settle(OWNER, 'code', 5)).toHaveLength(5);

    await spend(app, OWNER, 30, 100);
    expect((await sendCode(app, '203.0.113.30', { address: OWNER })).statusCode).toBe(429);
    // Past the ceiling too.
    expect((await sendCode(app, '127.0.0.1', { address: OWNER })).statusCode).toBe(200);
    expect(await settle(OWNER, 'code', 36)).toHaveLength(36);
  }, 120_000);

  it('does not let a third party who spends the tiers from other IPs stop the owner’s reset', async () => {
    const app = await boot();
    await registerPasswordAccount(app, OWNER);
    // The third party spends the address-and-IP tier of nine IPs, three each.
    for (let ip = 1; ip <= 9; ip++) {
      for (let i = 0; i < 4; i++) {
        await sendCode(app, `198.51.100.${ip}`, { address: OWNER, floor: false });
      }
    }
    // The owner, on an IP the account does not know, still gets the code.
    expect((await sendCode(app, '203.0.113.40', { address: OWNER })).statusCode).toBe(200);
    expect(await settle(OWNER, 'code', 28)).toHaveLength(28);

    // The third party drives the address to its ceiling.
    await spend(app, OWNER, 2, 102);
    // The owner meets the 429, never a quiet drop, and the notice's pass.
    expect((await sendCode(app, '203.0.113.40', { address: OWNER })).statusCode).toBe(429);
    const pass = await noticedPass(OWNER);
    const { id } = await openPass(app, pass);
    const passHash = await passHashOf(app, id as string);
    expect(passHash).toBeDefined();

    expect((await sendCode(app, '203.0.113.40', { address: OWNER, passHash })).statusCode).toBe(
      200
    );
    expect(await settle(OWNER, 'code', 31)).toHaveLength(31);
  }, 120_000);
});
