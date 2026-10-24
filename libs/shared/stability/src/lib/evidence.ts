/**
 * The forms evidence for a promotion condition takes (ADR-018 §5). Pure: a
 * path's existence is checked by the caller, which has the file system.
 */

/**
 * What one piece of evidence is.
 *
 * - `rfc`: an RFC number, `RFC 9449`.
 * - `issue`: an issue or pull request of this repository, `#476`.
 * - `link`: an `https` URL.
 * - `path`: a path from the repository root, with an optional `#section`. It
 *   must exist.
 */
export type EvidenceKind = 'rfc' | 'issue' | 'link' | 'path';

const RFC_PATTERN = /^RFC [1-9]\d*$/;
const ISSUE_PATTERN = /^#[1-9]\d*$/;
const LINK_PATTERN = /^https:\/\/[^\s/]\S*$/;
const PATH_PATTERN = /^[A-Za-z0-9_.@-]+(?:\/[A-Za-z0-9_.@-]+)*(?:#[A-Za-z0-9_.-]+)?$/;

/**
 * The kind of a piece of evidence, or `null` when it has none of the four
 * forms. A path may not be absolute and may not step out of the repository.
 */
export function evidenceKind(evidence: string): EvidenceKind | null {
  if (RFC_PATTERN.test(evidence)) return 'rfc';
  if (ISSUE_PATTERN.test(evidence)) return 'issue';
  if (LINK_PATTERN.test(evidence)) return 'link';
  if (!PATH_PATTERN.test(evidence)) return null;
  const segments = evidencePath(evidence).split('/');
  return segments.some((segment) => segment === '.' || segment === '..') ? null : 'path';
}

/** The file part of a `path` evidence: everything before its `#section`. */
export function evidencePath(evidence: string): string {
  const at = evidence.indexOf('#');
  return at === -1 ? evidence : evidence.slice(0, at);
}

/** The section of a `path` evidence, after its `#`, or `undefined` when it names none. */
export function evidenceSection(evidence: string): string | undefined {
  const at = evidence.indexOf('#');
  return at === -1 ? undefined : evidence.slice(at + 1);
}
