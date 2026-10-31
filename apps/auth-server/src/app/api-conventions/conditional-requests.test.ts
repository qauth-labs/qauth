import { PreconditionRequiredError } from '@qauth-labs/shared-errors';
import type { FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import { UnsupportedMediaTypeError } from '../helpers/api-request-errors';
import {
  entityTagOf,
  entityTagValue,
  ifMatchAllows,
  requireIfMatch,
  requireMergePatch,
} from './conditional-requests';

const request = (headers: Record<string, string | undefined>) =>
  ({ headers }) as unknown as FastifyRequest;

describe('conditional requests (#524)', () => {
  it('tags a representation with a strong entity tag that changes with any member', () => {
    const tag = entityTagOf({ a: 1, b: 'x' });

    expect(tag).toMatch(/^"[A-Za-z0-9_-]{43}"$/);
    expect(entityTagOf({ a: 1, b: 'x' })).toBe(tag);
    expect(entityTagOf({ a: 1, b: 'y' })).not.toBe(tag);
    expect(ifMatchAllows(tag, entityTagValue(tag))).toBe(true);
    expect(ifMatchAllows(`W/${tag}`, entityTagValue(tag))).toBe(false);
    expect(ifMatchAllows(entityTagOf({ a: 2 }), entityTagValue(tag))).toBe(false);
  });

  it('refuses an update without If-Match with 428, before validation', async () => {
    await expect(requireIfMatch(request({}))).rejects.toThrow(PreconditionRequiredError);
    await expect(requireIfMatch(request({ 'if-match': '"x"' }))).resolves.toBeUndefined();
  });

  it('takes only a JSON Merge Patch as an update body (415 otherwise)', async () => {
    await expect(
      requireMergePatch(request({ 'content-type': 'application/merge-patch+json; charset=utf-8' }))
    ).resolves.toBeUndefined();
    for (const contentType of ['application/json', undefined, 'text/plain']) {
      await expect(requireMergePatch(request({ 'content-type': contentType }))).rejects.toThrow(
        UnsupportedMediaTypeError
      );
    }
  });
});
