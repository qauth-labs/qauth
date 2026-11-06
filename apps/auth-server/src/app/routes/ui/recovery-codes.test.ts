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
import { buildRealmUrl } from '../../helpers/realm-url';
import recoveryCodeRoutes from './recovery-codes';

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
const RECOVERY_CODES = stepUrn('recovery_codes');
const RECOVERY_CODE = stepUrn('recovery_code');
const CODES = [
  'abcd-efgh-ijkl-mnop',
  'bcde-fghi-jklm-nopq',
  'cdef-ghij-klmn-opqr',
  'defg-hijk-lmno-pqrs',
  'efgh-ijkl-mnop-qrst',
  'fghi-jklm-nopq-rstu',
  'ghij-klmn-opqr-stuv',
  'hijk-lmno-pqrs-tuvw',
  'ijkl-mnop-qrst-uvwx',
  'jklm-nopq-rstu-vwxy',
];

/** A step view of the interaction at `name`, as `readInteractionStep` answers it. */
const viewAt = (name: string, error?: string) =>
  ({
    step: { name, params: {}, alternatives: [], ...(error === undefined ? {} : { error }) },
    csrf: CSRF,
    revision: 3,
    expiresAt: Date.now() + 60_000,
    deadline: Date.now() + 60_000,
  }) as never;

/**
 * The recovery codes' pages (#649): "save your recovery codes" shows the set
 * once to the flow cookie's browser, and "use a recovery code" asks for one;
 * both post to the Interaction API's answer endpoint, and neither is cached.
 */
describe('the recovery-code pages (#649)', () => {
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
    await app.register(recoveryCodeRoutes, { prefix: '/ui' });
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  const action = () => buildRealmUrl(REALM, `/interaction/v1-rc.0/${ID}/answer`);

  describe('GET /ui/recovery-codes/:id', () => {
    const open = (headers: Record<string, string> = {}) =>
      app.inject({ method: 'GET', url: `/ui/recovery-codes/${ID}`, headers });

    it('shows the set once, with the confirmation the step needs, never cached', async () => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue({
        step: RECOVERY_CODES,
        data: { codes: CODES },
        current: { name: RECOVERY_CODES, params: { count: 10 }, alternatives: [] },
      });
      vi.mocked(readInteractionStep).mockResolvedValue(viewAt(RECOVERY_CODES));

      const response = await open({ 'sec-fetch-site': 'same-origin' });

      expect(response.statusCode).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers['content-type']).toContain('text/html');
      for (const code of CODES) expect(response.body).toContain(`<code>${code}</code>`);
      expect(response.body).toContain(`action="${action()}"`);
      expect(response.body).toContain(`name="type" value="${RECOVERY_CODES}"`);
      expect(response.body).toContain(`name="csrf" value="${CSRF}"`);
      expect(response.body).toMatch(/name="acknowledged" value="true" required/);
      expect(response.body).toContain('nonce="style-nonce"');
      expect(readInteractionPersonalData).toHaveBeenCalledWith(expect.anything(), ID);
    });

    it('refuses a page another site opened, before reading the interaction', async () => {
      const response = await open({ 'sec-fetch-site': 'cross-site' });

      expect(response.statusCode).toBe(403);
      expect(refuseForbidden).toHaveBeenCalledWith(expect.anything(), 'origin');
      expect(readInteractionPersonalData).not.toHaveBeenCalled();
      expect(response.body).not.toContain('abcd-efgh');
    });

    it('sends an interaction at another step to its ceremony page', async () => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue({
        step: RECOVERY_CODE,
        data: { identifier: 'alice@example.com' },
        current: { name: RECOVERY_CODE, params: {}, alternatives: [] },
      });

      const response = await open();

      expect(response.statusCode).toBe(303);
      expect(response.headers.location).toBe(buildRealmUrl(REALM, `/ui/interaction/${ID}`));
      expect(response.headers.location).not.toContain('abcd');
    });

    it('answers its own page, 410, for an interaction that has ended or a malformed id', async () => {
      vi.mocked(readInteractionPersonalData).mockRejectedValue(new InteractionExpiredError());

      const ended = await open();
      const malformed = await app.inject({ method: 'GET', url: '/ui/recovery-codes/nope' });

      for (const response of [ended, malformed]) {
        expect(response.statusCode).toBe(410);
        expect(response.headers['cache-control']).toBe('no-store');
        expect(response.body).toContain('This sign-in has ended');
      }
    });

    it('shows nothing from personal data that is not a set', async () => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue({
        step: RECOVERY_CODES,
        data: { codes: ['<script>alert(1)</script>', ...CODES.slice(1)] },
        current: { name: RECOVERY_CODES, params: { count: 10 }, alternatives: [] },
      });

      const response = await open();

      expect(response.statusCode).toBe(500);
      expect(response.body).not.toContain('<script>');
    });
  });

  describe('GET /ui/recovery-code/:id', () => {
    const open = () => app.inject({ method: 'GET', url: `/ui/recovery-code/${ID}` });

    it('asks for one code, posting to the answer endpoint, never cached', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(viewAt(RECOVERY_CODE));

      const response = await open();

      expect(response.statusCode).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.body).toContain(`action="${action()}"`);
      expect(response.body).toContain(`name="type" value="${RECOVERY_CODE}"`);
      expect(response.body).toContain(`name="csrf" value="${CSRF}"`);
      expect(response.body).toContain('name="recovery_code"');
      expect(response.body).not.toContain('role="alert"');
      // The step read needs no flow cookie: no personal data is read.
      expect(readInteractionPersonalData).not.toHaveBeenCalled();
    });

    it('says a refused code did not work', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewAt(RECOVERY_CODE, 'invalid_credentials')
      );

      const response = await open();

      expect(response.statusCode).toBe(200);
      expect(response.body).toContain('role="alert"');
      expect(response.body).toContain('That code did not work');
      expect(response.body).toContain('aria-invalid="true"');
    });

    it('asks for a code offered beside the first steps, for a lost passkey (#655)', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue({
        step: {
          name: stepUrn('webauthn_get'),
          params: {},
          alternatives: [stepUrn('identifier'), RECOVERY_CODE],
          // The current step's error is not the code's.
          error: 'invalid_credentials',
        },
        csrf: CSRF,
        revision: 3,
        expiresAt: Date.now() + 60_000,
        deadline: Date.now() + 60_000,
      } as never);

      const response = await open();

      expect(response.statusCode).toBe(200);
      expect(response.body).toContain(`name="type" value="${RECOVERY_CODE}"`);
      expect(response.body).toContain(`name="csrf" value="${CSRF}"`);
      expect(response.body).not.toContain('role="alert"');
    });

    it('sends an interaction at another step to its ceremony page', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(viewAt(stepUrn('password')));

      const response = await open();

      expect(response.statusCode).toBe(303);
      expect(response.headers.location).toBe(buildRealmUrl(REALM, `/ui/interaction/${ID}`));
    });

    it('answers its own page, 410, for an interaction that has ended', async () => {
      vi.mocked(readInteractionStep).mockRejectedValue(new InteractionExpiredError());

      const response = await open();

      expect(response.statusCode).toBe(410);
      expect(response.body).toContain('This sign-in has ended');
    });
  });
});
