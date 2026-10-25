import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectStandardError } from '../../helpers/error-shape';
import { getJsonObject } from '../../helpers/http';

const { baseUrl, ssfTransmitter } = wireConfig();

const PUSH = 'urn:ietf:rfc:8935';

/** The endpoint members of SSF 1.0 §7.1 the transmitter publishes. */
const ENDPOINTS = [
  'configuration_endpoint',
  'status_endpoint',
  'add_subject_endpoint',
  'remove_subject_endpoint',
  'verification_endpoint',
] as const;

/**
 * SSF 1.0 §7 — the transmitter metadata at `/.well-known/ssf-configuration`.
 * A default deployment runs no transmitter and answers 404; a target whose
 * realm runs one (`QAUTH_WIRE_SSF_TRANSMITTER=1`) must serve valid metadata.
 */
describe('SSF 1.0 §7 — the transmitter metadata', () => {
  const url = serverPath(baseUrl, '/.well-known/ssf-configuration');

  it.runIf(!ssfTransmitter)('answers 404 while the transmitter is off', async () => {
    await expectStandardError(await fetch(url, { redirect: 'manual' }), { status: 404 });
  });

  it.runIf(ssfTransmitter)(
    'serves the metadata as JSON, naming the issuer (§7.1, §7.2)',
    async () => {
      const { body } = await getJsonObject(url);
      expect(body['issuer']).toBe(baseUrl);
      expect(body['spec_version']).toBe('1_0');
      expect(body['delivery_methods_supported']).toContain(PUSH);
      expect(['ALL', 'NONE']).toContain(body['default_subjects']);
    }
  );

  it.runIf(ssfTransmitter)('names endpoints and a jwks_uri under the issuer’s origin', async () => {
    const { body } = await getJsonObject(url);
    const origin = new URL(baseUrl).origin;
    for (const member of ['jwks_uri', ...ENDPOINTS]) {
      expect(body[member], member).toBeTypeOf('string');
      expect(new URL(body[member] as string).origin, member).toBe(origin);
    }
    const { body: discovery } = await getJsonObject(
      serverPath(baseUrl, '/.well-known/openid-configuration')
    );
    expect(body['jwks_uri']).toBe(discovery['jwks_uri']);
  });
});
