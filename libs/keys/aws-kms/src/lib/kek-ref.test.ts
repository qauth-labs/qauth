import { describe, expect, it } from 'vitest';

import { formatKekRef, parseKekRef } from './kek-ref';

const ARN = 'arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const MATERIAL = 'a'.repeat(64);

describe('kekRef', () => {
  it('is the key ARN and the key material ID, or the ARN alone', () => {
    expect(formatKekRef(ARN, MATERIAL)).toBe(`${ARN}#${MATERIAL}`);
    expect(formatKekRef(ARN, undefined)).toBe(ARN);
  });

  it('parses back into both parts', () => {
    expect(parseKekRef(`${ARN}#${MATERIAL}`)).toEqual({ keyArn: ARN, keyMaterialId: MATERIAL });
    expect(parseKekRef(ARN)).toEqual({ keyArn: ARN, keyMaterialId: undefined });
  });

  it.each(['', 'a#b', 'with space', 'tab\t', 'é'])(
    'refuses the key material ID %j, which would not parse back',
    (keyMaterialId) => {
      expect(() => formatKekRef(ARN, keyMaterialId)).toThrow(TypeError);
    }
  );
});
