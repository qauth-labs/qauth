import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { GITHUB_REPO_BLOB_BASE } from '../lib/records';
import { resolveRepoRoot } from '../lib/repo-root';
import {
  type MinimalTreeNode,
  remarkRewriteRecordLinks,
  rewriteRecordLink,
} from './remark-rewrite-record-links';

/**
 * Task 10 (#356): rewrites the in-tree `.md` links inside the rendered
 * records (`docs/adr/*.md`, `docs/security/*.md`) into working site
 * routes — or, for a real repo file the records collection does not
 * render, a GitHub blob URL — at build time. See the plugin's own doc
 * comment for the five-bucket rule this file tests.
 */

const REPO_ROOT = resolveRepoRoot();
const GITHUB_BLOB_BASE_URL = GITHUB_REPO_BLOB_BASE;
const OPTIONS = { repoRoot: REPO_ROOT, githubBlobBaseUrl: GITHUB_BLOB_BASE_URL };

function link(url: string): MinimalTreeNode {
  return { type: 'link', url, children: [{ type: 'text' }] };
}

function sourcePath(...segments: string[]): string {
  return join(REPO_ROOT, 'docs', ...segments);
}

describe('rewriteRecordLink — the four buckets', () => {
  it('leaves an external https:// link untouched', () => {
    const node = link('https://openid.net/specs/openid-connect-core-1_0.html');
    rewriteRecordLink(node, sourcePath('adr', '002-identifier-abstraction.md'), OPTIONS);
    expect(node.url).toBe('https://openid.net/specs/openid-connect-core-1_0.html');
  });

  it('leaves a mailto: link untouched', () => {
    const node = link('mailto:security@qauth.dev');
    rewriteRecordLink(node, sourcePath('adr', '001-jwt-key-management.md'), OPTIONS);
    expect(node.url).toBe('mailto:security@qauth.dev');
  });

  it('leaves a bare #anchor untouched', () => {
    const node = link('#spec-status-2026-07-19');
    rewriteRecordLink(node, sourcePath('adr', '004-wallet-agnostic-federation.md'), OPTIONS);
    expect(node.url).toBe('#spec-status-2026-07-19');
  });

  it('rewrites an in-tree .md link (no anchor) to the target record’s site route', () => {
    const node = link('./007-mcp-first-positioning.md');
    rewriteRecordLink(node, sourcePath('adr', '003-credential-provider-interface.md'), OPTIONS);
    expect(node.url).toBe('/reference/records/adr/007-mcp-first-positioning/');
  });

  it('rewrites an in-tree .md link WITH an anchor to the site route, keeping the anchor', () => {
    const node = link('./004-wallet-agnostic-federation.md#decision');
    rewriteRecordLink(node, sourcePath('adr', '009-wallet-account-resolution.md'), OPTIONS);
    expect(node.url).toBe('/reference/records/adr/004-wallet-agnostic-federation/#decision');
  });

  it('resolves a cross-directory link from an ADR into docs/security', () => {
    const node = link('../security/005-pqc-hybrid-signing-review.md');
    rewriteRecordLink(node, sourcePath('adr', '005-pqc-hybrid-signing.md'), OPTIONS);
    expect(node.url).toBe('/reference/records/security/005-pqc-hybrid-signing-review/');
  });

  it('resolves a cross-directory link from the security review back into docs/adr', () => {
    const node = link('../adr/005-pqc-hybrid-signing.md');
    rewriteRecordLink(node, sourcePath('security', '005-pqc-hybrid-signing-review.md'), OPTIONS);
    expect(node.url).toBe('/reference/records/adr/005-pqc-hybrid-signing/');
  });

  it('resolves ./README.md within docs/adr to the records README route', () => {
    const node = link('./README.md');
    rewriteRecordLink(node, sourcePath('adr', '004-wallet-agnostic-federation.md'), OPTIONS);
    expect(node.url).toBe('/reference/records/adr/README/');
  });

  it('rewrites a link to a real repo file the records collection does NOT render to a GitHub blob URL — the brief’s own example', () => {
    // `../../MVP-PRD.md` is the Task 10 brief's own illustrative case: a
    // real file (verified below) that stays a repo file, never a rendered
    // record. It does not occur literally in the current ADR corpus (see
    // the exhaustive real-tree test), so this is a synthetic but faithful
    // stand-in — same shape, same resolution, same decision.
    expect(existsSync(join(REPO_ROOT, 'MVP-PRD.md'))).toBe(true);
    const node = link('../../MVP-PRD.md');
    rewriteRecordLink(node, sourcePath('adr', '007-mcp-first-positioning.md'), OPTIONS);
    expect(node.url).toBe(`${GITHUB_BLOB_BASE_URL}/MVP-PRD.md`);
  });

  it('rewrites a link to the EUDI regulatory drift log (a real, un-rendered docs/ root file) to a GitHub blob URL, anchor included', () => {
    const node = link(
      '../eudi-regulatory-drift-log.md#3-cir-eu-20242979-article-14-and-annex-v--pseudonyms--superseded'
    );
    rewriteRecordLink(node, sourcePath('adr', '009-wallet-account-resolution.md'), OPTIONS);
    expect(node.url).toBe(
      `${GITHUB_BLOB_BASE_URL}/docs/eudi-regulatory-drift-log.md#3-cir-eu-20242979-article-14-and-annex-v--pseudonyms--superseded`
    );
  });

  it("leaves a repo-root-ABSOLUTE /docs/... link untouched — the docs collection's own, different convention (bucket 0)", () => {
    // `/docs/agent-authorization.md` is the real, pre-existing form used
    // throughout apps/docs-site/src/content/docs (e.g.
    // integrate/api-reference.md, operate/keys.md) — a repo-root-relative
    // reference, NOT resolved relative to the linking file the way `./`
    // and `../` are. Without the plugin's explicit bucket-0 check, this
    // would still happen to come out untouched today (`path.resolve` on an
    // absolute second argument discards `dirname(sourcePath)` and lands on
    // a filesystem-root path that doesn't exist) — but that would be
    // correct by accident of `path.resolve` semantics, not by a rule this
    // plugin states, and would diverge silently from `link-resolution.ts`,
    // which DOES treat a leading `/` as repo-root-relative
    // (`join(repoRoot, pathPart)`) and would find this exact file.
    expect(existsSync(join(REPO_ROOT, 'docs', 'agent-authorization.md'))).toBe(true);
    const node = link('/docs/agent-authorization.md');
    rewriteRecordLink(node, sourcePath('adr', '007-mcp-first-positioning.md'), OPTIONS);
    expect(node.url).toBe('/docs/agent-authorization.md');
  });

  it('leaves a repo-root-ABSOLUTE /docs/... link with an anchor untouched too (bucket 0)', () => {
    const node = link('/docs/agent-authorization.md#1-agent-client-type-is_agent');
    rewriteRecordLink(node, sourcePath('adr', '007-mcp-first-positioning.md'), OPTIONS);
    expect(node.url).toBe('/docs/agent-authorization.md#1-agent-client-type-is_agent');
  });

  it('MUTATION: leaves a .md link untouched when it resolves to nothing on disk', () => {
    const node = link('./999-does-not-exist.md');
    rewriteRecordLink(node, sourcePath('adr', '001-jwt-key-management.md'), OPTIONS);
    expect(node.url).toBe('./999-does-not-exist.md');
  });

  it('MUTATION: does not touch a relative link that is not markdown (e.g. an image)', () => {
    const node = link('./diagram.png');
    rewriteRecordLink(node, sourcePath('adr', '001-jwt-key-management.md'), OPTIONS);
    expect(node.url).toBe('./diagram.png');
  });

  it('MUTATION: a link with no url (non-link node) is a no-op, not a crash', () => {
    const node: MinimalTreeNode = { type: 'link' };
    expect(() =>
      rewriteRecordLink(node, sourcePath('adr', '001-jwt-key-management.md'), OPTIONS)
    ).not.toThrow();
    expect(node.url).toBeUndefined();
  });
});

describe('remarkRewriteRecordLinks — tree traversal (the unified attacher)', () => {
  it('rewrites every link nested anywhere in the tree, including inside a list item', () => {
    // Named references, kept instead of indexing back into `tree` after the
    // transform — the point of this test is the traversal, not re-deriving
    // tree shape via non-null-asserted child lookups.
    const inTreeLink = link('./002-identifier-abstraction.md');
    const externalLink = link('https://example.com/spec');
    const nestedAnchorLink = link('#same-page-anchor');
    const tree: MinimalTreeNode = {
      type: 'root',
      children: [
        { type: 'paragraph', children: [inTreeLink, externalLink] },
        {
          type: 'list',
          children: [
            {
              type: 'listItem',
              children: [{ type: 'paragraph', children: [nestedAnchorLink] }],
            },
          ],
        },
      ],
    };

    const transformer = remarkRewriteRecordLinks(OPTIONS);
    transformer(tree, { path: sourcePath('adr', '003-credential-provider-interface.md') });

    expect(inTreeLink.url).toBe('/reference/records/adr/002-identifier-abstraction/');
    expect(externalLink.url).toBe('https://example.com/spec'); // untouched
    expect(nestedAnchorLink.url).toBe('#same-page-anchor'); // untouched, found 3 levels deep
  });

  it('is a no-op (does not throw) when the vfile carries no resolvable path', () => {
    const onlyLink = link('./001-jwt-key-management.md');
    const tree: MinimalTreeNode = { type: 'root', children: [onlyLink] };
    const transformer = remarkRewriteRecordLinks(OPTIONS);
    expect(() => transformer(tree, {})).not.toThrow();
    expect(onlyLink.url).toBe('./001-jwt-key-management.md'); // untouched: no source path to resolve against
  });
});

describe('rewriteRecordLink — the real docs/adr and docs/security corpus, enumerated exhaustively', () => {
  // Every markdown link `[text](url)` extracted from every file in
  // docs/adr/ and docs/security/ — not a sample. Mirrors the extraction
  // regex `src/invariants/link-resolution.ts` uses (`MD_LINK_RE`), since
  // this test exists to characterise the SAME corpus that guard would see
  // if it ever scanned records (it doesn't — see the Task 10 report).
  const MD_LINK_RE = /\[[^\]]*\]\(([^)]+)\)/g;

  interface ExtractedLink {
    file: string; // repo-relative, e.g. docs/adr/004-wallet-agnostic-federation.md
    url: string;
  }

  function extractAllLinks(): ExtractedLink[] {
    const links: ExtractedLink[] = [];
    for (const subdir of ['adr', 'security'] as const) {
      const dir = join(REPO_ROOT, 'docs', subdir);
      for (const fileName of readdirSync(dir).sort()) {
        if (!fileName.endsWith('.md')) continue;
        const file = `docs/${subdir}/${fileName}`;
        const content = readFileSync(join(dir, fileName), 'utf8');
        const re = new RegExp(MD_LINK_RE.source, MD_LINK_RE.flags);
        let match: RegExpExecArray | null;
        while ((match = re.exec(content))) {
          links.push({ file, url: match[1] });
        }
      }
    }
    return links;
  }

  it('extracts exactly 144 links across the 9 ADRs, the ADR README, and the security review — the corpus the counts below are checked against', () => {
    // A fixed count, not a lower bound: this test's whole point is that the
    // categorisation below is checked against the FULL corpus, not a
    // sample. If a future ADR amendment changes the link count, this
    // assertion is meant to force a look at the new numbers below too.
    expect(extractAllLinks()).toHaveLength(144);
  });

  it('every link falls into exactly one of the four buckets, with none left unresolved', () => {
    const links = extractAllLinks();
    let untouchedExternalOrAnchor = 0;
    let rewrittenToRoute = 0;
    let rewrittenToBlob = 0;
    let leftUnresolved = 0;

    for (const { file, url } of links) {
      const node = link(url);
      rewriteRecordLink(node, join(REPO_ROOT, file), OPTIONS);

      const isBareAnchorOrExternal = url.startsWith('#') || /^[a-z][a-z0-9+.-]*:/i.test(url);
      const pathPart = url.split('#', 1)[0] ?? '';
      const isInTreeMdLink = !isBareAnchorOrExternal && pathPart.endsWith('.md');
      const resultUrl = node.url ?? url; // rewriteRecordLink only ever leaves this a string

      if (!isInTreeMdLink) {
        expect(resultUrl).toBe(url); // bucket 1: untouched, byte-for-byte
        untouchedExternalOrAnchor += 1;
        continue;
      }
      if (resultUrl.startsWith('/reference/records/')) {
        rewrittenToRoute += 1;
      } else if (resultUrl.startsWith(GITHUB_BLOB_BASE_URL)) {
        rewrittenToBlob += 1;
      } else {
        expect(resultUrl).toBe(url); // bucket 4: untouched because unresolved
        leftUnresolved += 1;
      }
    }

    // Counts verified by direct enumeration of the corpus (see the Task 10
    // report): 66 external links, 17 bare #anchors, 56 links into another
    // rendered record, 5 links to the EUDI regulatory drift log (the only
    // un-rendered docs/ file the current corpus links to — 4 from ADR-009,
    // 1 from docs/adr/README.md). An earlier draft of this test asserted 57
    // and 4 here, from a by-hand tally of the corpus printout that miscounted
    // the EUDI drift log links by one; this run caught it, which is the
    // point of enumerating mechanically instead of eyeballing a sample.
    expect(untouchedExternalOrAnchor).toBe(66 + 17);
    expect(rewrittenToRoute).toBe(56);
    expect(rewrittenToBlob).toBe(5);
    expect(leftUnresolved).toBe(0);
  });
});
