import { describe, expect, it } from 'vitest';

import { buildIssueStatesQuery, parseIssueStatesResponse } from './issue-state-resolution';

/**
 * The resolution half of the issue-state guard (#399).
 *
 * `scripts/check-issue-state-claims.mts` makes exactly one network call. Every
 * decision either side of it — what to ask for, and what an answer means — lives
 * here so it can be tested offline. What is deliberately NOT tested is `fetch`
 * itself; a suite that needed a GitHub token would be skipped in exactly the
 * situations this guard exists for.
 *
 * `onFailure` is typed as never-returning, so these tests pass a thrower.
 */

function thrower(code: number, message: string): never {
  throw new Error(`[${code}] ${message}`);
}

describe('buildIssueStatesQuery', () => {
  it('asks for every number in ONE request', () => {
    const query = buildIssueStatesQuery('qauth-labs', 'qauth', [231, 376, 377]);
    expect(query).toContain('i231: issueOrPullRequest(number: 231)');
    expect(query).toContain('i376: issueOrPullRequest(number: 376)');
    expect(query).toContain('i377: issueOrPullRequest(number: 377)');
    // One `query {` and one `repository(` — not three requests' worth.
    expect(query.match(/repository\(/g)).toHaveLength(1);
  });

  it('uses issueOrPullRequest, so a PR number cannot kill the whole batch', () => {
    // Asking for `issue(number:)` on a pull request is a hard GraphQL error,
    // which would take down every other lookup batched with it. A `#NNN` in
    // prose may name either.
    const query = buildIssueStatesQuery('qauth-labs', 'qauth', [391]);
    expect(query).toContain('issueOrPullRequest');
    expect(query).not.toMatch(/\bissue\(number/);
    expect(query).toContain('... on Issue { number state }');
  });
});

describe('parseIssueStatesResponse', () => {
  const payload = (repository: unknown) => ({ data: { repository } });

  it('maps GraphQL OPEN/CLOSED onto the guard vocabulary', () => {
    const states = parseIssueStatesResponse(
      payload({
        i377: { number: 377, state: 'OPEN' },
        i379: { number: 379, state: 'CLOSED' },
      }),
      thrower
    );

    expect(states.get(377)).toBe('open');
    expect(states.get(379)).toBe('closed');
  });

  it('omits an unresolvable reference rather than guessing at it', () => {
    // A PR number, a deleted issue or a typo resolves to `{}` (the inline
    // fragment matches nothing). Leaving it OUT is what makes
    // `findClosedIssuesNamedAsOpen` report it as unresolved — one rule about
    // what counts as a failure, in one place, rather than two.
    const states = parseIssueStatesResponse(
      payload({ i377: { number: 377, state: 'OPEN' }, i999: {} }),
      thrower
    );

    expect(states.has(377)).toBe(true);
    expect(states.has(999)).toBe(false);
  });

  it('fails on a GraphQL errors array', () => {
    expect(() =>
      parseIssueStatesResponse({ errors: [{ message: 'Bad credentials' }] }, thrower)
    ).toThrow(/\[2\].*Bad credentials/);
  });

  it('fails on a response with no repository — a changed shape must not read as clean', () => {
    expect(() => parseIssueStatesResponse({ data: {} }, thrower)).toThrow(/\[2\].*repository/);
    expect(() => parseIssueStatesResponse(null, thrower)).toThrow(/\[2\].*repository/);
    expect(() => parseIssueStatesResponse('not json at all', thrower)).toThrow(/\[2\]/);
  });

  it('fails when NOTHING resolved, rather than reporting a clean tree', () => {
    // The dangerous case: a wrong token scope or a renamed repository returns a
    // well-formed response resolving nothing. An empty map would make every
    // reference "unresolved" — which is caught downstream — but failing here
    // names the actual cause instead of listing every reference as suspect.
    expect(() => parseIssueStatesResponse(payload({ i377: {}, i379: null }), thrower)).toThrow(
      /\[2\].*resolved no issues/
    );
  });
});
