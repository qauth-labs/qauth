import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface AnchorablePage {
  /** Identifier used in violation reports — a repo-relative path is ideal. */
  id: string;
  content: string;
}

export interface AnchorViolation {
  page: string;
  anchor: string;
  symbol?: string;
  reason: string;
}

interface BacktickSpan {
  content: string;
  start: number;
  end: number;
}

function findBacktickSpans(text: string): BacktickSpan[] {
  const spans: BacktickSpan[] = [];
  const re = /`([^`\n]+)`/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text))) {
    spans.push({ content: match[1], start: match.index, end: match.index + match[0].length });
  }
  return spans;
}

/** `path:line` — e.g. `apps/auth-server/src/main.ts:88`. No line ranges, no bare filenames. */
const ANCHOR_SHAPE_RE = /^([\w./-]+\.[A-Za-z0-9]+):(\d+)$/;
/** A plain identifier, quoted beside an anchor to say "this is the symbol at that line". */
const SYMBOL_SHAPE_RE = /^[A-Za-z_$][\w$]*$/;
/** Punctuation allowed between an anchor and an adjacent quoted symbol: `, `, ` → `, etc. */
const ADJACENT_GAP_RE = /^[\s,()→:-]{0,4}$/;

function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Look at the immediate neighbour spans for a plain-identifier symbol quoted beside the anchor. */
function findAdjacentSymbol(
  spans: BacktickSpan[],
  index: number,
  text: string
): string | undefined {
  const prev = spans[index - 1];
  const current = spans[index];
  if (
    prev &&
    SYMBOL_SHAPE_RE.test(prev.content) &&
    ADJACENT_GAP_RE.test(text.slice(prev.end, current.start))
  ) {
    return prev.content;
  }
  const next = spans[index + 1];
  if (
    next &&
    SYMBOL_SHAPE_RE.test(next.content) &&
    ADJACENT_GAP_RE.test(text.slice(current.end, next.start))
  ) {
    return next.content;
  }
  return undefined;
}

/**
 * Every `path:line`-shaped anchor must name a file that exists in the
 * repository. Where a plain identifier is quoted immediately beside it
 * (the repo's own convention — see `docs/oidf-op-certification-runbook.md`,
 * e.g. `` `assertDistinctJwksKeyIds`, `fastify-plugin-jwt.ts:344` ``), that
 * symbol must still appear in the named file.
 *
 * Line numbers are deliberately NOT asserted — they drift on every
 * unrelated edit above them, and a guard that fails on innocent edits gets
 * disabled. The file and the quoted symbol are the durable part.
 */
export function findInvalidAnchors(pages: AnchorablePage[], repoRoot: string): AnchorViolation[] {
  const violations: AnchorViolation[] = [];

  for (const page of pages) {
    const spans = findBacktickSpans(page.content);
    for (let i = 0; i < spans.length; i += 1) {
      const span = spans[i];
      const anchorMatch = span.content.match(ANCHOR_SHAPE_RE);
      if (!anchorMatch) continue;

      const [, filePart] = anchorMatch;
      const absolutePath = join(repoRoot, filePart);
      if (!existsSync(absolutePath)) {
        violations.push({
          page: page.id,
          anchor: span.content,
          reason: `"${filePart}" does not exist in the repository`,
        });
        continue;
      }

      const symbol = findAdjacentSymbol(spans, i, page.content);
      if (symbol) {
        const fileContents = readFileSync(absolutePath, 'utf8');
        const wordBoundary = new RegExp(`\\b${escapeForRegExp(symbol)}\\b`);
        if (!wordBoundary.test(fileContents)) {
          violations.push({
            page: page.id,
            anchor: span.content,
            symbol,
            reason: `quoted symbol "${symbol}" was not found in ${filePart}`,
          });
        }
      }
    }
  }

  return violations;
}
