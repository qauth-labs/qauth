import { existsSync } from 'node:fs';
import { join } from 'node:path';

export interface EvidenceEntry {
  feature: string;
  /** Phrases that identify a mention of this feature in prose (matched case-insensitively). */
  aliases: string[];
  /** Paths, relative to the repo root, whose existence proves the feature shipped. ALL must exist. */
  evidencePaths: string[];
}

/**
 * Feature → evidence. Adding a forbidden-sentence list instead of this table
 * is exactly the design this guard rejects: a sentence list rots the moment
 * prose is reworded, while a path either exists or it doesn't. Every path
 * here is verified to exist by `status-claims.test.ts`'s
 * "the evidence table itself is accurate" case — an invented path would
 * silently make its feature's claims un-checkable, not fail loudly, so it
 * has to be caught in its own right.
 */
export const FEATURE_EVIDENCE: EvidenceEntry[] = [
  {
    feature: 'PQC / hybrid signing',
    aliases: ['pqc', 'hybrid signing', 'post-quantum', 'ml-dsa'],
    // The HYBRID_SIGNING_ENABLED flag that gates issuance lives in auth-server's
    // env config; the crypto implementation itself lives in libs/core/crypto.
    evidencePaths: ['libs/core/crypto', 'apps/auth-server/src/config/env.ts'],
  },
  {
    feature: 'Wallet federation / OID4VP',
    // `oid4vc` is deliberately NOT an alias here. The evidence path proves OID4VP
    // *verification* shipped; OID4VC *issuance* did not (there is no
    // libs/server/federation/src/oid4vci). Aliasing the two made this row treat an
    // accurate "OID4VC is planned" statement as drift — a false positive on a true
    // sentence, which is worse than the miss it was meant to catch.
    aliases: ['wallet federation', 'oid4vp'],
    evidencePaths: ['libs/server/federation/src/oid4vp'],
  },
  {
    feature: 'Identifier abstraction (ADR-002)',
    aliases: ['identifier abstraction', 'identifier-abstraction migration', 'adr-002'],
    evidencePaths: ['libs/infra/db/src/lib/schema/identity.ts'],
  },
  {
    feature: 'Agent-native authorization',
    aliases: ['agent-native authorization', 'agent-native authz', 'agent-native'],
    evidencePaths: ['apps/auth-server/src/app/helpers/scope-modes.ts'],
  },
  {
    feature: 'Environment-aware authorization',
    aliases: ['environment-aware authorization', 'environment-aware authz'],
    evidencePaths: ['apps/auth-server/src/app/helpers/environment-policy.ts'],
  },
  {
    feature: 'API keys',
    aliases: ['api keys', 'api-keys', 'static developer api key', 'static api key'],
    evidencePaths: ['apps/auth-server/src/app/routes/clients/api-keys.ts'],
  },
];

export interface ScannablePage {
  /** Identifier used in violation reports — a repo-relative path is ideal. */
  id: string;
  content: string;
  /**
   * The page-scoped escape hatch (`unbuiltClaims: true` in frontmatter).
   * `README.md` and `docs/README.md` have no frontmatter, so callers pass
   * `undefined` for them — treated as "not exempt", never as a crash.
   */
  unbuiltClaims?: boolean;
}

export interface StatusClaimViolation {
  file: string;
  feature: string;
  matchedPhrase: string;
  excerpt: string;
}

/**
 * "Deferred", "not yet implemented", "coming soon" and near-equivalents.
 * `deferred` excludes the "not deferred" case (a negative-lookbehind) so a
 * sentence correcting the record — e.g. README.md's own "is implemented and
 * shipping today, not deferred" aside about ADR-006 — is never itself
 * flagged as the violation.
 *
 * `📋` is included because it is not decoration: README.md's own legend defines
 * it as "planned", and the architecture diagram used it to mark OID4VP planned
 * 25 lines after the same file said wallet login works end to end. Matching the
 * symbol rather than the word "planned" is deliberate — the drift this missed
 * was written as `(📋 Phase 4)`, with the word nowhere in the sentence.
 *
 * Note this regex is applied to raw markdown, fenced blocks included. That is
 * why the diagram above is reachable at all, and it is intentional: a status
 * claim drawn inside an ASCII box misleads exactly as much as one in prose.
 */
const STATUS_PHRASE_RE =
  /(?:(?<!\bnot\s)\bdeferred\b)|(?:\bnot yet implemented\b)|(?:\bnot implemented\b)|(?:\bcoming soon\b)|(?:\bnot yet built\b)|(?:\bnot built yet\b)|(?:\bto be implemented\b)|(?:\bunimplemented\b)|📋/gi;

interface Paragraph {
  text: string;
  start: number;
}

/** Blank-line-delimited chunks. A wrapped sentence stays one chunk; a real topic break doesn't. */
function splitParagraphs(content: string): Paragraph[] {
  const paragraphs: Paragraph[] = [];
  const blankLineRe = /\n[ \t]*\n+/g;
  let start = 0;
  let match: RegExpExecArray | null;
  while ((match = blankLineRe.exec(content))) {
    paragraphs.push({ text: content.slice(start, match.index), start });
    start = match.index + match[0].length;
  }
  paragraphs.push({ text: content.slice(start), start });
  return paragraphs;
}

// A bullet/checkbox/numbered line, optionally itself inside a `>` blockquote
// (README.md's roadmap recap quotes each T0–T5 status as `> - ✅ **T0 …**`).
const LIST_LINE_RE = /^\s*(?:>\s*)?(?:[-*+]\s|\d+[.)]\s)/;

/**
 * A line carrying the `📋` status symbol. Such a line is its own claim about its
 * own subject, so it becomes its own segment and absorbs no continuation lines.
 *
 * This matters only because `📋` occurs where the word-phrases do not: inside the
 * big ASCII diagram and repo-tree fences in README.md, which contain no blank
 * lines and are therefore ONE paragraph each. Scoped by paragraph, a `📋` marking
 * `auth-ui/` as planned sat in the same segment as an unrelated "API keys"
 * mention 40 lines away and reported it as drift. Every one of those blocks marks
 * one subject per line, so the line is the honest unit.
 */
const SYMBOL_LINE_RE = /📋/;

function isListParagraph(text: string): boolean {
  const firstLine = text.split(/\r?\n/).find((line) => line.trim().length > 0);
  return firstLine !== undefined && LIST_LINE_RE.test(firstLine);
}

interface Segment {
  text: string;
  /** Offset of this segment within its paragraph's text. */
  start: number;
  isList: boolean;
}

/**
 * Break a paragraph into segments: each bullet/checkbox/numbered line starts
 * its OWN segment (plus any indented continuation lines that follow it,
 * before the next bullet), and any leading or interleaved non-list lines
 * form their own prose segment. Every list line starts a new segment even
 * when adjacent to another one — sibling bullets are independent claims,
 * not one blob (see `computeScope`).
 *
 * Splits with a CAPTURING `/(\r?\n)/` rather than a plain `/\r?\n/`, so each
 * matched terminator survives in the output and its REAL length (1 for
 * `\n`, 2 for `\r\n`) drives both the running `offset` and the text rebuilt
 * for a continuation line. A flat `+1` here would silently drift every
 * later segment's `start` — and therefore `computeScope`'s
 * `localStart - segment.start` slicing — on CRLF input. `.gitattributes`
 * forces LF for `*.md` (which covers `README.md`, `docs/README.md`, and
 * every `.md` content page), but NOT `.mdx` — so this stays correct instead
 * of resting on a guarantee that doesn't fully cover this function's real
 * callers.
 */
function splitSegments(paragraphText: string): Segment[] {
  const parts = paragraphText.split(/(\r?\n)/); // [line, terminator, line, terminator, ..., line]
  const segments: Segment[] = [];
  let offset = 0;
  let current: Segment | undefined;
  for (let i = 0; i < parts.length; i += 2) {
    const line = parts[i];
    const precedingTerminator = i > 0 ? parts[i - 1] : '';
    if (SYMBOL_LINE_RE.test(line)) {
      // Own segment, and `current` is cleared so the NEXT line starts fresh
      // rather than being absorbed as this claim's continuation.
      if (current) segments.push(current);
      segments.push({ text: line, start: offset, isList: false });
      current = undefined;
    } else if (LIST_LINE_RE.test(line)) {
      if (current) segments.push(current);
      current = { text: line, start: offset, isList: true };
    } else if (current) {
      current.text += precedingTerminator + line;
    } else {
      current = { text: line, start: offset, isList: false };
    }
    const terminatorAfter = parts[i + 1] ?? '';
    offset += line.length + terminatorAfter.length;
  }
  if (current) segments.push(current);
  return segments;
}

/** Cut `text` at the nearest `;` on each side of the match, falling back to the text's own edges. */
function clauseWithin(text: string, localStart: number, localEnd: number): string {
  const leftSemicolon = text.lastIndexOf(';', Math.max(0, localStart - 1));
  const rightSemicolon = text.indexOf(';', localEnd);
  const clauseStart = leftSemicolon === -1 ? 0 : leftSemicolon + 1;
  const clauseEnd = rightSemicolon === -1 ? text.length : rightSemicolon;
  return text.slice(clauseStart, clauseEnd);
}

/**
 * The text a status-phrase match is judged against — NOT a fixed character
 * window. Real docs prose puts unrelated shipped/unbuilt claims right next
 * to each other, at two different granularities, and a fixed window
 * conflates both:
 *
 *   - Same paragraph, semicolon-separated clauses: "T0–T3 … complete (…,
 *     agent-native authZ, …); T4 (wallet federation …) deferred". A window
 *     wide enough to reach "wallet federation" (the genuine claim) was also
 *     wide enough to reach "agent-native authZ" (shipped, unrelated) a
 *     clause earlier.
 *   - A flat bullet list where each item is independently tagged, whether as
 *     plain bullets ("- API key management ✅ … - Federation provider
 *     configuration UI 📋 (deferred with wallet federation, T4)") or as a
 *     blockquoted status recap ("> - ✅ **T5 …** … > - 📋 **T4 …
 *     (deferred …)**"). A window false-flagged `API keys` and
 *     `Environment-aware authorization` purely for sharing a list with an
 *     unrelated deferred bullet.
 *
 * Two structural rules replace the window:
 *   - Clause bounding: cut at the nearest `;` on each side of the match,
 *     within whichever segment (see below) the match falls in.
 *   - List handling, which differs by direction:
 *     - The match falls on a bullet/checkbox/blockquoted-bullet LINE: scope
 *       narrows to just that ONE bullet's segment — a sibling bullet's
 *       feature must not be pulled in, even when they share one markdown
 *       paragraph (no blank line between them).
 *     - The match falls in a PROSE segment (not itself a bullet) that is
 *       immediately followed by one or more bullet segments — in the same
 *       paragraph, or, failing that, in the very next paragraph after a
 *       blank line (`**📋 Deferred — long-term platform**` followed by the
 *       bullets naming what's deferred): scope WIDENS to include those
 *       bullets, because the prose introduces and governs them.
 */
function computeScope(content: string, matchIndex: number, matchLength: number): string {
  const paragraphs = splitParagraphs(content);
  const paragraphIndex = paragraphs.findIndex(
    (paragraph, i) =>
      matchIndex >= paragraph.start &&
      (i === paragraphs.length - 1 || matchIndex < paragraphs[i + 1].start)
  );
  const paragraph = paragraphs[paragraphIndex];
  const localStart = matchIndex - paragraph.start;
  const localEnd = localStart + matchLength;

  const segments = splitSegments(paragraph.text);
  const segIndex = [...segments.keys()].reverse().find((i) => segments[i].start <= localStart) ?? 0;
  const segment = segments[segIndex];
  const clause = clauseWithin(segment.text, localStart - segment.start, localEnd - segment.start);

  if (segment.isList) return clause;

  let scope = clause;
  let i = segIndex + 1;
  while (i < segments.length && segments[i].isList) {
    scope += `\n${segments[i].text}`;
    i += 1;
  }
  if (i === segments.length) {
    const next = paragraphs[paragraphIndex + 1];
    if (next && isListParagraph(next.text)) scope += `\n${next.text}`;
  }
  return scope;
}

function containsAlias(scopeText: string, alias: string): boolean {
  const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`\\b${escaped}\\b`, 'i').test(scopeText);
}

/**
 * Content may not claim a shipped feature is deferred/unbuilt. Only
 * features whose evidence paths actually exist on disk are checked —
 * evidence that has moved or been deleted is treated as "not confirmed
 * shipped" rather than trusted blindly, so a future refactor can't silently
 * widen what this guard enforces.
 */
export function findStaleStatusClaims(
  pages: ScannablePage[],
  evidence: EvidenceEntry[],
  repoRoot: string
): StatusClaimViolation[] {
  const shipped = evidence.filter((entry) =>
    entry.evidencePaths.every((path) => existsSync(join(repoRoot, path)))
  );

  const violations: StatusClaimViolation[] = [];

  for (const page of pages) {
    if (page.unbuiltClaims) continue; // the page-scoped escape hatch

    const flaggedFeatures = new Set<string>();
    const pattern = new RegExp(STATUS_PHRASE_RE.source, STATUS_PHRASE_RE.flags);
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(page.content))) {
      const scope = computeScope(page.content, match.index, match[0].length);

      for (const entry of shipped) {
        if (flaggedFeatures.has(entry.feature)) continue;
        if (entry.aliases.some((alias) => containsAlias(scope, alias))) {
          flaggedFeatures.add(entry.feature);
          violations.push({
            file: page.id,
            feature: entry.feature,
            matchedPhrase: match[0],
            excerpt: scope.replace(/\s+/g, ' ').trim(),
          });
        }
      }
    }
  }

  return violations;
}

/* -------------------------------------------------------------------------- */
/*        Second class of check: issue-state claims (#399)                     */
/* -------------------------------------------------------------------------- */

/**
 * A `#NNN` reference found inside an open-work construction.
 *
 * WHY THIS EXISTS. The evidence-path check above resolves "shipped" by asking
 * whether a path exists on disk. It has no notion of a GitHub issue's state, so
 * a sentence reading "Open: … key-storage assurance (#379) …" stays green
 * forever after `#379` closes — nothing about it is falsifiable from the
 * filesystem. That is exactly what happened: `#379` closed 2026-08-26 and
 * `MVP-PRD.md` was wrong within 24 hours, while `status.ts` — the file whose own
 * header says "Every claim below must stay true of the tree at HEAD" — still
 * named it. This makes that class of claim falsifiable.
 */
export interface OpenWorkIssueRef {
  /** Page id, as supplied by the caller — a repo-relative path is ideal. */
  file: string;
  /** 1-indexed line the reference sits on. */
  line: number;
  /** The referenced issue number. */
  issue: number;
  /** The open-work phrase that put this reference in scope. */
  trigger: string;
  /** One line of surrounding text, for the failure message. */
  excerpt: string;
}

export interface IssueStateViolation extends OpenWorkIssueRef {
  reason: string;
}

/**
 * The constructions that turn a following `#NNN` into a claim about an issue's
 * state. Deliberately a short, explicit list rather than "any `#NNN` anywhere":
 * this repository cites issue numbers constantly as ATTRIBUTION — "added in
 * #226", "the #308 gate", "(#379 review, finding 3)" — and those are correct
 * precisely because the issue is closed. Flagging every reference would make the
 * check unusable and would be wrong on the merits.
 *
 * `Remaining:` and `Open:` are matched with their colon because the bare words
 * are far too common in prose ("the remaining scopes", "an open redirect").
 */
const OPEN_WORK_TRIGGER_RE =
  /(?:\bOpen:)|(?:\bRemaining:)|(?:\bstill open\b)|(?:\bstill to (?:come|do|land|ship)\b)|(?:\byet to (?:come|be|land|ship)\b)|(?:\bremaining (?:T\d+ )?work\b)|(?:\bstill (?:being|under) )/gi;

/** `#123`, not `#12345678` (a colour) and not part of a longer token. */
const ISSUE_REF_RE = /(?<![\w#])#(\d{1,5})\b/g;

/**
 * How far past a trigger a `#NNN` still counts as governed by it.
 *
 * Bounded by structure, not a character window. The lists this has to read run
 * to several clauses — "Open: HAIP profile wiring (#377), key-storage assurance
 * (#379), the real-wallet pass (#376), and the tracking epic (#231)." — and a
 * window wide enough for the last of those would run into whatever came after.
 *
 * The scope ends at the earliest of:
 *
 *   - the end of the sentence (`.` followed by whitespace, or by end of input);
 *   - a blank line, i.e. the end of the paragraph;
 *   - the start of the next list item.
 *
 * A SOFT line break does not end it. That distinction is the whole difficulty:
 * this repository hard-wraps markdown at about 80 columns, so the four-issue
 * list above spans three physical lines. An earlier draft stopped at any `\n`
 * and saw only `#377` — correctly scoping bullets while silently truncating
 * every wrapped prose list, which is where the drift this check exists for
 * actually lives.
 */
function scopeAfterTrigger(content: string, triggerEnd: number): string {
  const rest = content.slice(triggerEnd);
  const boundaries = [
    rest.search(/\.(?:\s|$)/), // sentence end
    rest.search(/\n[ \t]*\n/), // blank line — paragraph end
    rest.search(/\n\s*(?:[-*+]\s|\d+[.)]\s)/), // next list item
  ].filter((index) => index !== -1);

  return boundaries.length === 0 ? rest : rest.slice(0, Math.min(...boundaries));
}

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (content[i] === '\n') line += 1;
  }
  return line;
}

/**
 * Every `#NNN` this content presents as OPEN work.
 *
 * Pure and offline by design: resolving the numbers is the caller's job (see
 * `scripts/check-issue-state-claims.mjs`), so the extraction can be tested
 * exhaustively against fixtures without a network or a token.
 */
export function findOpenWorkIssueRefs(pages: ScannablePage[]): OpenWorkIssueRef[] {
  const refs: OpenWorkIssueRef[] = [];

  for (const page of pages) {
    if (page.unbuiltClaims) continue; // same page-scoped escape hatch

    const seen = new Set<string>();
    const triggers = new RegExp(OPEN_WORK_TRIGGER_RE.source, OPEN_WORK_TRIGGER_RE.flags);
    let trigger: RegExpExecArray | null;

    while ((trigger = triggers.exec(page.content))) {
      const triggerEnd = trigger.index + trigger[0].length;
      const scope = scopeAfterTrigger(page.content, triggerEnd);

      const issues = new RegExp(ISSUE_REF_RE.source, ISSUE_REF_RE.flags);
      let ref: RegExpExecArray | null;
      while ((ref = issues.exec(scope))) {
        const issue = Number(ref[1]);
        const absolute = triggerEnd + ref.index;
        const key = `${issue}@${absolute}`;
        if (seen.has(key)) continue;
        seen.add(key);
        refs.push({
          file: page.id,
          line: lineOf(page.content, absolute),
          issue,
          trigger: trigger[0],
          excerpt: `${trigger[0]}${scope}`.replace(/\s+/g, ' ').trim().slice(0, 200),
        });
      }
    }
  }

  return refs;
}

/**
 * The refs whose issues are CLOSED — prose that presents finished work as
 * outstanding.
 *
 * `states` must carry an entry for every ref. A number the caller could not
 * resolve is a violation in its own right rather than a pass: a guard that
 * silently skips what it could not check reports green while checking nothing,
 * which is worse than no guard at all.
 */
export function findClosedIssuesNamedAsOpen(
  refs: OpenWorkIssueRef[],
  states: Map<number, 'open' | 'closed'>
): IssueStateViolation[] {
  const violations: IssueStateViolation[] = [];

  for (const ref of refs) {
    const state = states.get(ref.issue);
    if (state === undefined) {
      violations.push({ ...ref, reason: `issue #${ref.issue} could not be resolved` });
    } else if (state === 'closed') {
      violations.push({ ...ref, reason: `issue #${ref.issue} is closed but listed as open work` });
    }
  }

  return violations;
}
