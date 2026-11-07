import { stepUrn } from '@qauth-labs/shared-interaction-contract';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { supplyRequestRealm, testRealm } from '../../../testing/request-realm';
import {
  readInteractionPersonalData,
  readInteractionStep,
  refuseForbidden,
} from '../../helpers/interaction';
import { InteractionExpiredError } from '../../helpers/interaction-expired';
import { encodeQrCode, renderQrCodeSvg } from '../../helpers/qr-code';
import { buildRealmUrl } from '../../helpers/realm-url';
import { groupedSecret } from '../../helpers/totp-pages';
import totpRoutes from './totp';

vi.mock('../../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_LIMIT_LENIENT: 600,
    AUTHORIZE_RATE_WINDOW: 60,
  },
}));

vi.mock('../../helpers/interaction', () => ({
  readInteractionStep: vi.fn(),
  readInteractionPersonalData: vi.fn(),
  refuseForbidden: vi.fn(async () => {
    throw Object.assign(new Error('Forbidden'), { statusCode: 403 });
  }),
}));

const REALM = testRealm({ id: 'realm-1' });
const ID = 'i'.repeat(43);
const CSRF = 'csrf-value-of-the-step-view';
const TOTP = stepUrn('totp');
const TOTP_SETUP = stepUrn('totp_setup');
const RECOVERY_CODE = stepUrn('recovery_code');
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const URI = `otpauth://totp/id.example.test:alice%40example.com?secret=${SECRET}&issuer=id.example.test&algorithm=SHA1&digits=6&period=30`;

/** A step view of the interaction at `name`, as `readInteractionStep` answers it. */
const viewAt = (name: string, opts: { error?: string; alternatives?: string[] } = {}) =>
  ({
    step: {
      name,
      params: {},
      alternatives: opts.alternatives ?? [],
      ...(opts.error === undefined ? {} : { error: opts.error }),
    },
    csrf: CSRF,
    revision: 3,
    expiresAt: Date.now() + 60_000,
    deadline: Date.now() + 60_000,
  }) as never;

/** The set-up step's personal data, as `readInteractionPersonalData` answers it. */
const setupPersonal = (data: Record<string, unknown> = { secret: SECRET, otpauth_uri: URI }) => ({
  step: TOTP_SETUP,
  data: { identifier: 'alice@example.com', ...data },
  current: {
    name: TOTP_SETUP,
    params: { algorithm: 'SHA1', digits: 6, period: 30 },
    alternatives: [],
  },
});

/**
 * The authenticator app's pages (#653): "enter the code" asks for the `totp`
 * step's code, "set up an authenticator app" shows the new secret to the flow
 * cookie's browser only; both post to the Interaction API's answer endpoint,
 * and neither is cached.
 */
describe('the authenticator app pages (#653)', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    vi.mocked(readInteractionStep).mockReset();
    vi.mocked(readInteractionPersonalData).mockReset();
    vi.mocked(refuseForbidden).mockClear();
    app = Fastify({ logger: false });
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    app.decorateReply('cspNonce', null as never);
    app.addHook('onRequest', async (_request, reply) => {
      reply.cspNonce = { script: 'script-nonce', style: 'style-nonce' };
    });
    supplyRequestRealm(app, REALM);
    await app.register(totpRoutes, { prefix: '/ui' });
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  const action = () => buildRealmUrl(REALM, `/interaction/v1-rc.0/${ID}/answer`);
  const ceremony = () => buildRealmUrl(REALM, `/ui/interaction/${ID}`);

  describe('GET /ui/totp/:id', () => {
    const open = () => app.inject({ method: 'GET', url: `/ui/totp/${ID}` });

    it('asks for the six-digit code, posting to the answer endpoint, never cached', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(viewAt(TOTP));

      const response = await open();

      expect(response.statusCode).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers['content-type']).toContain('text/html');
      expect(response.body).toContain(`action="${action()}"`);
      expect(response.body).toContain(`name="type" value="${TOTP}"`);
      expect(response.body).toContain(`name="csrf" value="${CSRF}"`);
      expect(response.body).toMatch(/name="otp"[^>]*pattern="\[0-9\]\{6\}"/);
      expect(response.body).toContain('autocomplete="one-time-code"');
      expect(response.body).toContain('nonce="style-nonce"');
      expect(response.body).not.toContain('role="alert"');
      // No recovery code is offered unless the step offers one.
      expect(response.body).not.toContain(RECOVERY_CODE);
      // The step read needs no flow cookie: no personal data is read.
      expect(readInteractionPersonalData).not.toHaveBeenCalled();
    });

    it('says a refused code did not work', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewAt(TOTP, { error: 'invalid_credentials' })
      );

      const response = await open();

      expect(response.body).toContain('role="alert"');
      expect(response.body).toContain('That code did not work');
      expect(response.body).toContain('aria-invalid="true"');
    });

    it('offers a recovery code in its place when the step does', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewAt(TOTP, { alternatives: [RECOVERY_CODE] })
      );

      const response = await open();

      expect(response.body).toContain('Use a recovery code instead');
      expect(response.body).toContain(`name="type" value="${RECOVERY_CODE}"`);
      expect(response.body).toContain('name="recovery_code"');
    });

    it('sends an interaction at another step to its ceremony page', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(viewAt(stepUrn('password')));

      const response = await open();

      expect(response.statusCode).toBe(303);
      expect(response.headers.location).toBe(ceremony());
    });

    it('answers its own page, 410, for an interaction that has ended or a malformed id', async () => {
      vi.mocked(readInteractionStep).mockRejectedValue(new InteractionExpiredError());

      const ended = await open();
      const malformed = await app.inject({ method: 'GET', url: '/ui/totp/nope' });

      for (const response of [ended, malformed]) {
        expect(response.statusCode).toBe(410);
        expect(response.headers['cache-control']).toBe('no-store');
        expect(response.body).toContain('This sign-in has ended');
      }
    });
  });

  describe('GET /ui/totp-setup/:id', () => {
    const open = (headers: Record<string, string> = {}) =>
      app.inject({ method: 'GET', url: `/ui/totp-setup/${ID}`, headers });

    it('shows the secret as a QR code and as text, with the first code’s form, never cached', async () => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue(setupPersonal());
      vi.mocked(readInteractionStep).mockResolvedValue(viewAt(TOTP_SETUP));

      const response = await open({ 'sec-fetch-site': 'same-origin' });

      expect(response.statusCode).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      const qr = encodeQrCode(URI);
      expect(qr).toBeDefined();
      if (qr === undefined) return;
      // The QR code holds exactly the step's otpauth URI.
      expect(response.body).toContain(
        renderQrCodeSvg(qr, 'QR code containing the authenticator app key')
      );
      expect(response.body).toContain(groupedSecret(SECRET));
      expect(groupedSecret(SECRET)).toBe('JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP');
      expect(response.body).toContain(`action="${action()}"`);
      expect(response.body).toContain(`name="type" value="${TOTP_SETUP}"`);
      expect(response.body).toContain(`name="csrf" value="${CSRF}"`);
      expect(response.body).toContain('name="otp"');
      // The secret is never put in a URL.
      expect(response.body).not.toMatch(new RegExp(`(href|action)="[^"]*${SECRET}`));
      expect(readInteractionPersonalData).toHaveBeenCalledWith(expect.anything(), ID);
    });

    it('says a refused first code did not work', async () => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue(setupPersonal());
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewAt(TOTP_SETUP, { error: 'invalid_credentials' })
      );

      const response = await open();

      expect(response.body).toContain('That code did not work');
      expect(response.body).toContain('aria-invalid="true"');
    });

    it('refuses a page another site opened, before reading the interaction', async () => {
      const response = await open({ 'sec-fetch-site': 'cross-site' });

      expect(response.statusCode).toBe(403);
      expect(refuseForbidden).toHaveBeenCalledWith(expect.anything(), 'origin');
      expect(readInteractionPersonalData).not.toHaveBeenCalled();
      expect(response.body).not.toContain(SECRET);
    });

    it('sends an interaction at another step to its ceremony page, with no secret', async () => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue({
        step: TOTP,
        data: { identifier: 'alice@example.com' },
        current: { name: TOTP, params: { digits: 6 }, alternatives: [] },
      });

      const response = await open();

      expect(response.statusCode).toBe(303);
      expect(response.headers.location).toBe(ceremony());
    });

    it('shows nothing from personal data that is not a secret', async () => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue(
        setupPersonal({ secret: '<script>alert(1)</script>', otpauth_uri: URI })
      );

      const response = await open();

      expect(response.statusCode).toBe(500);
      expect(response.body).not.toContain('<script>');
    });

    it.each([
      ['a quote', `otpauth://totp/a"b?secret=${SECRET}`],
      ['an angle bracket', `otpauth://totp/a<b?secret=${SECRET}`],
      ['a bracket', `otpauth://totp/a[b?secret=${SECRET}`],
      ['a space', `otpauth://totp/a b?secret=${SECRET}`],
    ])('shows no URI holding %s, which the set-up never builds', async (_name, uri) => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue(
        setupPersonal({ secret: SECRET, otpauth_uri: uri })
      );

      const response = await open();

      expect(response.statusCode).toBe(500);
      expect(response.body).not.toContain(SECRET);
    });

    it('answers its own page, 410, for an interaction that has ended', async () => {
      vi.mocked(readInteractionPersonalData).mockRejectedValue(new InteractionExpiredError());

      const response = await open();

      expect(response.statusCode).toBe(410);
      expect(response.body).toContain('This sign-in has ended');
    });
  });
});
