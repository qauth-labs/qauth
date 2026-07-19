import { jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  getSignatureBackend,
  registerSignatureBackend,
  resetSignatureBackends,
} from './backend-registry';
import { CryptoVerificationError } from './errors';
import {
  PQC_ALG_ML_DSA_65,
  PQC_JOSE_ALG_POLICY_SPEC,
  PQC_JOSE_MLDSA_SPEC,
} from './hybrid-constants';
import { extractJwsSigningInput, signHybrid, verifyHybrid } from './hybrid-signing';
import { generateSigningKeyPair } from './key-management';

const ISSUER = 'https://auth.example.com';
const AUDIENCE = 'client-1';
// The operator-enabled set (#248 F7/F11). Every hybrid call site now resolves
// its ML-DSA backend through this allowlist instead of reaching for noble.
const PQC_ENABLED = ['EdDSA', 'ML-DSA-65'] as const;
const noble = getSignatureBackend('ML-DSA-65', PQC_ENABLED);

async function makeKeys() {
  const ed = await generateSigningKeyPair('EdDSA', { extractable: true });
  const mlDsa = noble.generateKeyPair({ extractable: true });
  return { ed, mlDsa };
}

const signOpts = {
  issuer: ISSUER,
  expiresIn: 900,
  audience: AUDIENCE,
  enabledSignatureAlgorithms: PQC_ENABLED,
};

describe('hybrid signing (#245) — carrier shape + AC#2 compatibility', () => {
  it('AC#2 GOLD PROOF: the hybrid token is a stock-jose-verifiable Ed25519 JWS', async () => {
    const { ed, mlDsa } = await makeKeys();
    const hybrid = await signHybrid(
      { sub: 'user-1', role: 'admin' },
      { ed: ed.privateKey, mlDsa: mlDsa.privateKey, edKid: 'ed-1', mlDsaKid: 'ed-1-mldsa' },
      signOpts
    );

    // Zero QAuth verify code — a stock JOSE verifier with NO PQC awareness.
    const { payload, protectedHeader } = await jwtVerify(hybrid.token, ed.publicKey, {
      algorithms: ['EdDSA'],
      issuer: ISSUER,
      audience: AUDIENCE,
    });
    expect(payload['sub']).toBe('user-1');
    expect(payload['role']).toBe('admin');
    // The classical verifier sees, and IGNORES, the non-critical PQC members.
    expect(protectedHeader.alg).toBe('EdDSA');
    expect(protectedHeader['pqc_alg']).toBe('ML-DSA-65');
    expect(protectedHeader['pqc_kid']).toBe('ed-1-mldsa');
    expect(protectedHeader['crit']).toBeUndefined();
  });

  it('carries the ML-DSA signature ALONGSIDE, never inside the compact string', async () => {
    const { ed, mlDsa } = await makeKeys();
    const hybrid = await signHybrid(
      { sub: 'u' },
      { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
      signOpts
    );
    // Compact JWS has exactly three segments; the PQC sig is a separate field.
    expect(hybrid.token.split('.')).toHaveLength(3);
    expect(hybrid.pqcAlg).toBe(PQC_ALG_ML_DSA_65);
    expect(hybrid.pqcSignature.length).toBeGreaterThan(0);
    expect(hybrid.token).not.toContain(hybrid.pqcSignature);
  });
});

describe('hybrid signing (#245) — PQC verification (AC#3)', () => {
  it('verifyHybrid verifies BOTH components and returns the claims', async () => {
    const { ed, mlDsa } = await makeKeys();
    const hybrid = await signHybrid(
      { sub: 'user-1' },
      { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
      signOpts
    );
    const claims = await verifyHybrid(
      hybrid,
      { ed: ed.publicKey, mlDsa: mlDsa.publicKey },
      {
        requirePqc: true,
        algorithms: ['EdDSA' as const],
        issuer: ISSUER,
        audience: AUDIENCE,
        enabledSignatureAlgorithms: PQC_ENABLED,
      }
    );
    expect(claims['sub']).toBe('user-1');
  });

  it('the ML-DSA signature verifies against exactly the JWS signing-input', async () => {
    const { ed, mlDsa } = await makeKeys();
    const hybrid = await signHybrid(
      { sub: 'u' },
      { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
      signOpts
    );
    const signingInput = extractJwsSigningInput(hybrid.token);
    const sig = new Uint8Array(Buffer.from(hybrid.pqcSignature, 'base64url'));
    expect(() => noble.verify(mlDsa.publicKey, signingInput, sig)).not.toThrow();
    // extractJwsSigningInput is the header.payload prefix.
    const expected = hybrid.token.slice(0, hybrid.token.lastIndexOf('.'));
    expect(new TextDecoder().decode(signingInput)).toBe(expected);
  });

  it('two signings of identical claims produce DIFFERENT pqc signatures (hedged), both valid', async () => {
    const { ed, mlDsa } = await makeKeys();
    const keys = { ed: ed.privateKey, mlDsa: mlDsa.privateKey };
    const a = await signHybrid({ sub: 'u' }, keys, signOpts);
    const b = await signHybrid({ sub: 'u' }, keys, signOpts);
    expect(a.pqcSignature).not.toBe(b.pqcSignature);
    const vkeys = { ed: ed.publicKey, mlDsa: mlDsa.publicKey };
    const vopts = {
      requirePqc: true,
      algorithms: ['EdDSA' as const],
      issuer: ISSUER,
      audience: AUDIENCE,
      enabledSignatureAlgorithms: PQC_ENABLED,
    };
    await expect(verifyHybrid(a, vkeys, vopts)).resolves.toBeDefined();
    await expect(verifyHybrid(b, vkeys, vopts)).resolves.toBeDefined();
  });
});

describe('hybrid signing (#245) — downgrade / stripping / mix-and-match', () => {
  const vopts = {
    requirePqc: true,
    algorithms: ['EdDSA' as const],
    issuer: ISSUER,
    audience: AUDIENCE,
    enabledSignatureAlgorithms: PQC_ENABLED,
  };

  it('rejects a stripped PQC signature when requirePqc is true', async () => {
    const { ed, mlDsa } = await makeKeys();
    const hybrid = await signHybrid(
      { sub: 'u' },
      { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
      signOpts
    );
    const stripped = { ...hybrid, pqcSignature: '' };
    await expect(
      verifyHybrid(stripped, { ed: ed.publicKey, mlDsa: mlDsa.publicKey }, vopts)
    ).rejects.toThrow(/downgrade/);
  });

  it('accepts a classical-only token when requirePqc is false', async () => {
    const { ed, mlDsa } = await makeKeys();
    const hybrid = await signHybrid(
      { sub: 'u' },
      { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
      signOpts
    );
    const claims = await verifyHybrid(
      { ...hybrid, pqcSignature: '' },
      { ed: ed.publicKey, mlDsa: mlDsa.publicKey },
      { ...vopts, requirePqc: false }
    );
    expect(claims['sub']).toBe('u');
  });

  it('rejects mix-and-match: token A body with token B PQC signature', async () => {
    const { ed, mlDsa } = await makeKeys();
    const keys = { ed: ed.privateKey, mlDsa: mlDsa.privateKey };
    const a = await signHybrid({ sub: 'a' }, keys, signOpts);
    const b = await signHybrid({ sub: 'b' }, keys, signOpts);
    const frankentoken = { ...a, pqcSignature: b.pqcSignature };
    await expect(
      verifyHybrid(frankentoken, { ed: ed.publicKey, mlDsa: mlDsa.publicKey }, vopts)
    ).rejects.toThrow(CryptoVerificationError);
  });

  it('a single-byte payload mutation breaks BOTH the Ed25519 and ML-DSA components', async () => {
    const { ed, mlDsa } = await makeKeys();
    const hybrid = await signHybrid(
      { sub: 'u' },
      { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
      signOpts
    );
    const [h, p, s] = hybrid.token.split('.');
    // Flip a base64url char in the payload segment.
    const tamperedPayload = p[0] === 'A' ? `B${p.slice(1)}` : `A${p.slice(1)}`;
    const tampered = { ...hybrid, token: [h, tamperedPayload, s].join('.') };
    // Ed25519 verify fails (classical component).
    await expect(
      jwtVerify(tampered.token, ed.publicKey, { algorithms: ['EdDSA'] })
    ).rejects.toThrow();
    // ML-DSA verify over the new signing-input also fails (PQC component).
    const sig = new Uint8Array(Buffer.from(tampered.pqcSignature, 'base64url'));
    expect(() =>
      noble.verify(mlDsa.publicKey, extractJwsSigningInput(tampered.token), sig)
    ).toThrow();
  });
});

describe('hybrid signing (#245/#274) — standards pinning', () => {
  it('pins the AKP JWK shape and ML-DSA-65 spelling to RFC 9964 (AC#4)', () => {
    // #274: NOT the composite-signature draft — that specifies the concatenated
    // construction QAuth deliberately does not implement.
    expect(PQC_JOSE_MLDSA_SPEC).toBe('RFC 9964');
    expect(PQC_JOSE_MLDSA_SPEC).not.toMatch(/composite/i);
    expect(PQC_JOSE_MLDSA_SPEC).not.toMatch(/draft-/i);
  });

  it('pins the alg-identifier policy to RFC 9864 (fully-specified algorithms)', () => {
    expect(PQC_JOSE_ALG_POLICY_SPEC).toBe('RFC 9864');
  });

  it('uses the exact IANA-registered ML-DSA-65 alg spelling from RFC 9964', () => {
    // Case and hyphenation are load-bearing for interop: a verifier matches
    // this string literally against the AKP JWK `alg`.
    expect(PQC_ALG_ML_DSA_65).toBe('ML-DSA-65');
  });
});

describe('hybrid signing (#248 F7/F11) — the operator allowlist is authoritative', () => {
  const CLASSICAL_ONLY = ['EdDSA'] as const;

  it('refuses to SIGN when SIGNING_ALGORITHM_MODE has not enabled ML-DSA-65', async () => {
    const { ed, mlDsa } = await makeKeys();

    await expect(
      signHybrid(
        { sub: 'u' },
        { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
        {
          ...signOpts,
          enabledSignatureAlgorithms: CLASSICAL_ONLY,
        }
      )
    ).rejects.toThrow(/'ML-DSA-65' is not enabled/);
  });

  it('names SIGNING_ALGORITHM_MODE so the operator knows which knob to turn', async () => {
    const { ed, mlDsa } = await makeKeys();

    await expect(
      signHybrid(
        { sub: 'u' },
        { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
        {
          ...signOpts,
          enabledSignatureAlgorithms: CLASSICAL_ONLY,
        }
      )
    ).rejects.toThrow(/SIGNING_ALGORITHM_MODE/);
  });

  it('aborts BEFORE producing a token — no silent classical-only downgrade', async () => {
    const { ed, mlDsa } = await makeKeys();
    // The gate is checked before the Ed25519 JWS is built, so a disabled
    // ML-DSA-65 can never leave a half-hybrid (classical-only) token behind
    // that a caller might mistake for a hybrid one.
    const error = await signHybrid(
      { sub: 'u' },
      { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
      {
        ...signOpts,
        enabledSignatureAlgorithms: CLASSICAL_ONLY,
      }
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toHaveProperty('token');
  });

  it('refuses to VERIFY a present PQC component when ML-DSA-65 is not enabled', async () => {
    const { ed, mlDsa } = await makeKeys();
    const hybrid = await signHybrid(
      { sub: 'u' },
      { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
      signOpts
    );

    await expect(
      verifyHybrid(
        hybrid,
        { ed: ed.publicKey, mlDsa: mlDsa.publicKey },
        {
          requirePqc: true,
          algorithms: ['EdDSA'],
          issuer: ISSUER,
          audience: AUDIENCE,
          enabledSignatureAlgorithms: CLASSICAL_ONLY,
        }
      )
    ).rejects.toThrow(/'ML-DSA-65' is not enabled/);
  });

  it('routes signing through a REGISTERED backend rather than hardcoding noble', async () => {
    const { ed, mlDsa } = await makeKeys();
    const calls: number[] = [];
    // Proves the call site really goes through getSignatureBackend: a
    // registered backend (as the native #244 backend would be) is what signs.
    registerSignatureBackend({
      ...noble,
      sign(privateKey, message) {
        calls.push(message.length);
        return noble.sign(privateKey, message);
      },
    });
    try {
      const hybrid = await signHybrid(
        { sub: 'u' },
        { ed: ed.privateKey, mlDsa: mlDsa.privateKey },
        signOpts
      );
      expect(calls).toHaveLength(1);
      expect(hybrid.pqcSignature.length).toBeGreaterThan(0);
    } finally {
      resetSignatureBackends();
    }
  });
});
