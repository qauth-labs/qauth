import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import { createWalletProvider } from '../providers/wallet.provider';
import { buildOid4vpAuthorizationRequest } from './authorization-request';
import { parseVpToken } from './direct-post';
import { generateOid4vpRequestSecrets } from './request-state';

/**
 * The safety boundary of issue #233, asserted rather than merely documented.
 *
 * #233 ships the OID4VP TRANSPORT: a wallet can now receive a presentation
 * request from QAuth and post a `vp_token` back, and QAuth will correlate the
 * `state`/`nonce` and structurally parse the response. That proves key
 * possession and freshness. It proves NOTHING about who the holder is.
 *
 * Under ADR-003 the auth engine mints a QAuth token for whatever `externalSub` a
 * `CredentialProvider` returns. So the moment `WalletProvider.verify()` resolves
 * a subject on the strength of this transport, any party able to round-trip the
 * endpoint self-registers as a user. Identity requires the credential to be
 * validated (#234) and its issuer to be trusted (#236) — and even then there is
 * no protocol-guaranteed stable wallet subject identifier (ADR-009 / #300).
 *
 * If a change makes this file fail, the change is wrong until #234 and #236 have
 * both landed. Do not soften the assertions to make it pass.
 */
describe('#233 safety boundary — the transport authenticates nobody', () => {
  it('WalletProvider.verify() STILL throws after the transport layer landed', async () => {
    const provider = createWalletProvider();

    await expect(provider.verify({ anything: 'a structurally valid response' })).rejects.toThrow(
      /not implemented/
    );
  });

  it('WalletProvider.extractAttributes() still throws', () => {
    expect(() => createWalletProvider().extractAttributes({} as never)).toThrow(/not implemented/);
  });

  it('a full request → response round-trip yields no identity of any kind', () => {
    const { state, nonce } = generateOid4vpRequestSecrets();

    const request = buildOid4vpAuthorizationRequest({
      profile: VERIFIER_PROFILES['oid4vp-1.0-base'],
      responseUri: 'https://auth.example.com/oid4vp/response',
      credentials: [
        { id: 'pid', format: 'dc+sd-jwt', typeValues: ['https://credentials.example.com/pid'] },
      ],
      state,
      nonce,
    });

    const presentations = parseVpToken(
      JSON.stringify({ pid: ['eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJwaWQifQ.c2ln~'] }),
      request.dcql_query,
      VERIFIER_PROFILES['oid4vp-1.0-base'].credentialFormats
    );

    // Everything the transport produced, flattened. None of it names a person.
    const surface = JSON.stringify(presentations);

    expect(presentations).toHaveLength(1);
    expect(surface).not.toContain('externalSub');
    expect(surface).not.toContain('external_sub');
    expect(surface).not.toContain('subject');
    expect(surface).not.toContain('userId');

    for (const presented of presentations) {
      expect(Object.keys(presented).sort()).toEqual(['format', 'presentation', 'queryId']);
    }
  });

  /**
   * A grep, deliberately. The types above cannot stop a future edit from adding
   * a subject-derivation helper next to them, and ADR-009 is explicit that this
   * layer must not derive or persist any `external_sub` — not from a JWK
   * thumbprint, not from a DID, not from an unverified `iss`.
   */
  it('no module in oid4vp/ derives an external_sub or a wallet subject', () => {
    const dir = __dirname;
    const sources = readdirSync(dir).filter(
      (file) => file.endsWith('.ts') && !file.endsWith('.test.ts')
    );

    expect(sources.length).toBeGreaterThan(0);

    const forbidden = [/externalSub\s*[:=]/, /external_sub\s*[:=]/, /thumbprint/i, /\bdid:/];

    for (const file of sources) {
      const contents = readFileSync(path.join(dir, file), 'utf8');
      // Strip block comments: the boundary is DESCRIBED in the JSDoc on purpose.
      const code = contents.replace(/\/\*[\s\S]*?\*\//g, '');

      for (const pattern of forbidden) {
        expect(
          pattern.test(code),
          `${file} appears to derive a wallet subject (${pattern}); identity is #234/#236, not #233.`
        ).toBe(false);
      }
    }
  });
});
