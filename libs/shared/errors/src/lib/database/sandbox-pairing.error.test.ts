import { describe, expect, it } from 'vitest';

import { SandboxPairingError } from './sandbox-pairing.error';

describe('SandboxPairingError', () => {
  it('is a 409 conflict that names its rule, with a fixed message', () => {
    const cause = new Error('check violation');
    const error = new SandboxPairingError('one_sandbox', cause);

    expect(error).toBeInstanceOf(SandboxPairingError);
    expect(error).toMatchObject({
      name: 'SandboxPairingError',
      statusCode: 409,
      code: 'CONFLICT',
      rule: 'one_sandbox',
      message: 'The live realm already has a sandbox realm',
      cause,
    });
  });

  it('says what each rule refuses', () => {
    expect(new SandboxPairingError('ceiling').message).toBe(
      "A sandbox realm's environment ceiling is staging or production, never development"
    );
    expect(new SandboxPairingError('live_realm_has_sandbox').message).toBe(
      'The realm has a sandbox realm: delete the sandbox realm first'
    );
  });
});
