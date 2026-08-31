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
 * comment for the six-bucket rule this file tests.
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

/** A page of the site's own `docs` content collection — the bucket 2b family. */
function contentDocsPath(...segments: string[]): string {
  return join(REPO_ROOT, 'apps', 'docs-site', 'src', 'content', 'docs', ...segments);
}

describe('rewriteRecordLink — the six buckets', () => {
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

  it('rewrites a relative .md link between two SITE CONTENT pages to the route Starlight serves, NOT a GitHub blob URL (bucket 2b)', () => {
    // The plugin is registered globally, so it also runs over every page of
    // the `docs` collection. Before bucket 2b, this link resolved to a real
    // file, was not a record, and therefore fell to bucket 3 — coming out as
    // `${GITHUB_BLOB_BASE_URL}/apps/docs-site/src/content/docs/extend/frontmatter.md`,
    // silently ejecting a reader of the rendered page into raw markdown
    // source. `link-resolution.ts` cannot catch that: it only asks whether
    // the relative target exists next to the page, which it does.
    expect(existsSync(contentDocsPath('extend', 'frontmatter.md'))).toBe(true);
    const node = link('./frontmatter.md');
    rewriteRecordLink(node, contentDocsPath('extend', 'architecture.md'), OPTIONS);
    expect(node.url).toBe('/extend/frontmatter/');
  });

  it('keeps the anchor when rewriting a site-content link to its route (bucket 2b)', () => {
    // `## Fields` in extend/frontmatter.md — a real heading, so the rewritten
    // link is one a reader can actually follow, not just a string match.
    const node = link('./frontmatter.md#fields');
    rewriteRecordLink(node, contentDocsPath('extend', 'architecture.md'), OPTIONS);
    expect(node.url).toBe('/extend/frontmatter/#fields');
  });

  it('collapses an index page to its lane route, the way Starlight serves it (bucket 2b)', () => {
    expect(existsSync(contentDocsPath('integrate', 'index.md'))).toBe(true);
    const node = link('../integrate/index.md');
    rewriteRecordLink(node, contentDocsPath('extend', 'architecture.md'), OPTIONS);
    expect(node.url).toBe('/integrate/');
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

  it('extracts exactly 197 links across the 11 ADRs, the ADR README, and the security review — the corpus the counts below are checked against', () => {
    // A fixed count, not a lower bound: this test's whole point is that the
    // categorisation below is checked against the FULL corpus, not a
    // sample. If a future ADR amendment changes the link count, this
    // assertion is meant to force a look at the new numbers below too.
    //
    // Rose 144 → 196 when main merged in: ADR-010 (acr assurance mapping) and
    // ADR-011 (enterprise managed authorization) joined the corpus, and ADR-007
    // was substantially expanded. Recounted mechanically, not adjusted by hand.
    //
    // 196 → 197 when #379 rewrote ADR-010 §5 and added §6: one new EXTERNAL
    // link, the OID4VCI 1.0 specification. Identified by diffing the extracted
    // link lists across the two revisions rather than by re-reading the ADR, so
    // the bucket it lands in below is a finding and not an assumption.
    //
    // 197 → 200 with #401's spec pin log: ADR-007's process note and two places
    // in ADR-011 now link `../spec-pin-log.md`. All three are in-tree `.md`
    // links to a document that is deliberately NOT a rendered record, so they
    // land in the BLOB bucket below — the same outcome, for the same reason, as
    // the EUDI drift log links already there.
    //
    // 200 → 203 with #374's ADR-012 (dynamic client ownership): one in-tree
    // link to ADR-007 (a rendered record → ROUTE bucket) and two external RFC
    // links (7591, 7592). Predicted from the ADR's own link list before
    // running, so the buckets below are a check and not a readjustment.
    expect(extractAllLinks()).toHaveLength(203);
  });

  it('every link falls into exactly one of the four outcomes, with none left unresolved', () => {
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
    // report): 93 external links, 17 bare #anchors, 78 links into another
    // rendered record, and 8 links to un-rendered docs/ files that fall back
    // to a GitHub blob URL. An earlier draft of this test asserted 57 and 4
    // here, from a by-hand tally of the corpus printout that miscounted the
    // EUDI drift log links by one; that run caught it, which is the point of
    // enumerating mechanically instead of eyeballing a sample.
    //
    // The blob bucket is 5 EUDI-regulatory-drift-log links, 3 links to
    // `docs/agent-authorization.md`, and (since #401) 3 to `docs/spec-pin-log.md`.
    // The middle group is worth understanding rather than just counting: that
    // guide moved to the site, so those ADR links land on its 3-line pointer
    // stub and the reader takes one extra hop to /integrate/agent-authorization/.
    // That is the migration's accepted trade-off (the epic's "moved guides
    // leave a pointer stub" decision), not a broken link — but if THAT group
    // grows, check whether a new ADR is pointing at a stub where it meant to
    // point at the guide.
    //
    // The pin-log group is the other kind: like the EUDI drift log beside it,
    // `docs/spec-pin-log.md` is an operational ledger that is deliberately not
    // rendered as a record, so a blob URL is the correct destination and not a
    // stub hop. 8 → 11 accordingly, with the external and route buckets
    // unchanged — which is the check that these really were in-tree links to an
    // unrendered doc.
    //
    // 93 → 94 external with #379's ADR-010 amendment (the OID4VCI 1.0 spec
    // URL). The three buckets below are unchanged by it, which is the check
    // that it really was an external link and not an in-tree one.
    //
    // ADR-012 (#374): 94 → 96 external (RFC 7591, RFC 7592) and 78 → 79 route
    // (its ADR-007 link). The blob bucket is unchanged, which is the check that
    // the ADR-007 link really did resolve to a rendered record rather than
    // falling back to a GitHub blob URL.
    expect(untouchedExternalOrAnchor).toBe(96 + 17);
    expect(rewrittenToRoute).toBe(79);
    expect(rewrittenToBlob).toBe(11);
    expect(leftUnresolved).toBe(0);
  });
});
