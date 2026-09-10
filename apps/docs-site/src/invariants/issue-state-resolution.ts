/**
 * Turning GitHub's answer into issue states (#399).
 *
 * Kept apart from `scripts/check-issue-state-claims.mts` so that everything
 * about the guard is unit-tested except the single `fetch` call itself. The
 * script is then a thin runner: build the scan set, extract, resolve, report.
 */

export type IssueState = 'open' | 'closed';

/** Reports a fatal input error. Implementations must not return. */
export type FailureReporter = (code: number, message: string) => never;

/**
 * Build the one-request GraphQL query for a batch of issue numbers.
 *
 * Batched deliberately: one request per reference would be dozens of calls on
 * every pull request, against a shared rate limit, for data that is a single
 * query.
 *
 * `issueOrPullRequest` rather than `issue` because a `#NNN` in prose may name
 * either, and asking for `issue` on a PR number is a hard GraphQL error that
 * would take the whole batch down. The inline fragment keeps only real issues;
 * anything else resolves to an empty object and is reported as unresolved.
 */
export function buildIssueStatesQuery(owner: string, repo: string, numbers: number[]): string {
  const fields = numbers
    .map((n) => `i${n}: issueOrPullRequest(number: ${n}) { ... on Issue { number state } }`)
    .join('\n');
  return `query { repository(owner: "${owner}", name: "${repo}") { ${fields} } }`;
}

/**
 * Turn a GraphQL payload into the state map, or fail.
 *
 * A number the query could not resolve — a pull request rather than an issue, a
 * deleted issue, a typo — is simply left out of the map. That is NOT a pass:
 * `findClosedIssuesNamedAsOpen` reports an unresolved reference as its own
 * violation. Reporting it there rather than here keeps one rule about what
 * counts as a failure instead of two.
 *
 * An EMPTY map, on the other hand, fails here. It means the query resolved
 * nothing at all — a wrong token scope, a renamed repository, a changed
 * response shape — and the difference between "checked everything, all fine"
 * and "checked nothing" must never be silent.
 */
export function parseIssueStatesResponse(
  payload: unknown,
  onFailure: FailureReporter
): Map<number, IssueState> {
  const body = payload as { errors?: unknown; data?: { repository?: unknown } } | null;

  if (body?.errors) {
    onFailure(2, `GitHub API returned errors: ${JSON.stringify(body.errors)}`);
  }

  const repository = body?.data?.repository;
  if (!repository || typeof repository !== 'object') {
    onFailure(2, 'GitHub API response had no repository field — shape changed?');
  }

  const states = new Map<number, IssueState>();
  for (const value of Object.values(repository as Record<string, unknown>)) {
    const entry = value as { number?: unknown; state?: unknown } | null;
    if (entry && typeof entry.number === 'number' && typeof entry.state === 'string') {
      states.set(entry.number, entry.state === 'OPEN' ? 'open' : 'closed');
    }
  }

  if (states.size === 0) {
    onFailure(2, 'GitHub API resolved no issues at all — token scope or query shape is wrong');
  }

  return states;
}
