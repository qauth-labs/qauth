import type { FastifyReply } from 'fastify';
import { describe, expect, it } from 'vitest';

import { allowFormActionTo } from './form-action';

/** A reply holding `csp` as its Content-Security-Policy. */
function replyWith(csp: string | undefined) {
  const headers: Record<string, string> = {};
  if (csp !== undefined) headers['content-security-policy'] = csp;
  const reply = {
    getHeader: (name: string) => headers[name.toLowerCase()],
    header: (name: string, value: string) => {
      headers[name.toLowerCase()] = value;
      return reply;
    },
  };
  return { reply: reply as unknown as FastifyReply, csp: () => headers['content-security-policy'] };
}

describe('allowFormActionTo', () => {
  const POLICY = "default-src 'self'; form-action 'self'; frame-ancestors 'none'";

  it("adds the client's source beside the page's own origin", () => {
    const { reply, csp } = replyWith(POLICY);
    allowFormActionTo(reply, 'https://claude.ai');
    expect(csp()).toBe(
      "default-src 'self'; form-action 'self' https://claude.ai; frame-ancestors 'none'"
    );
  });

  it("adds a native app's scheme, and adds it once", () => {
    const { reply, csp } = replyWith(POLICY);
    allowFormActionTo(reply, 'cursor:');
    allowFormActionTo(reply, 'cursor:');
    expect(csp()).toBe("default-src 'self'; form-action 'self' cursor:; frame-ancestors 'none'");
  });

  it('changes nothing for no source, a source it cannot write safely, or a page without the directive', () => {
    for (const source of [undefined, "https://a.example 'unsafe-inline'", 'https://a b', '*']) {
      const { reply, csp } = replyWith(POLICY);
      allowFormActionTo(reply, source);
      expect(csp()).toBe(POLICY);
    }
    const { reply, csp } = replyWith(undefined);
    allowFormActionTo(reply, 'https://claude.ai');
    expect(csp()).toBeUndefined();
  });
});
