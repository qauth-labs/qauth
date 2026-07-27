import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';
import { defineCollection } from 'astro:content';

// The frontmatter contract every docs page follows is documented in
// src/content/docs/extend/frontmatter.md. These two fields are not part of
// Starlight's own schema, so without this `extend:`, Zod would silently
// strip them from frontmatter instead of validating them.
export const collections = {
  docs: defineCollection({
    loader: docsLoader(),
    schema: docsSchema({
      extend: z.object({
        // ISO date (YYYY-MM-DD) the page's claims were last checked against
        // the tree. Presence is required and validated here; staleness is
        // not — nothing fails CI when the date goes stale (see
        // extend/frontmatter.md).
        lastVerified: z.iso.date(),
        // The unbuilt-claim marker. Declares that this page intentionally
        // describes something not yet built, so the status-claims drift
        // guard (src/invariants/status-claims.ts, issue #349) skips it. A
        // narrow, page-level escape hatch — not general-purpose
        // suppression. See extend/frontmatter.md.
        unbuiltClaims: z.boolean().default(false),
      }),
    }),
  }),

  // Task 10 (#356): the repository's design records — ADRs and the security
  // review — loaded from `docs/adr/` and `docs/security/` IN PLACE, never
  // copied or moved (see docs/adr/*.md, docs/security/*.md — cited by
  // `file:line` and by path from closed issues/PRs; those references must
  // keep resolving). A separate collection from `docs`, not a folder inside
  // it, for two independent reasons:
  //
  //  1. Starlight's own `docsLoader()` is hard-wired to `src/content/docs`
  //     (see `@astrojs/starlight/loaders.ts`, whose own comment says: "We
  //     still rely on the content collection folder structure to be fixed
  //     for now") — there is no supported way to point the `docs`
  //     collection's loader at a directory outside this Astro project.
  //  2. The `docs` collection's schema (above) REQUIRES `lastVerified`
  //     frontmatter. These files carry no frontmatter at all — by design,
  //     they are dated historical records, not living docs pages — and
  //     none is added here to require any; see extend/frontmatter.md and
  //     the Task 10 report for why a synthetic value is supplied only at
  //     render time, in `src/pages/reference/records/[...slug].astro`, and
  //     never written back into these source files.
  //
  // This split also settles the guard question the Task 10 brief raises:
  // the four drift guards (`src/invariants/*.ts`) find their scan set by
  // walking the PHYSICAL directory `src/content/docs` on disk
  // (`content-tree.ts`'s `loadContentTree`), not by asking Astro which
  // content collections exist. A `records` collection loaded from
  // `../../docs` therefore never appears in that walk regardless of what
  // it's named here — confirmed empirically (see the Task 10 report) — but
  // naming it separately from `docs` keeps that true structurally, not by
  // coincidence.
  records: defineCollection({
    loader: glob({
      base: '../../docs',
      // Non-recursive by design (`*.md`, not `**/*.md`): docs/adr/ and
      // docs/security/ are both flat today. If either ever grows a nested
      // subfolder, files inside it drop out of this collection SILENTLY —
      // no warning, no build failure, just absent from `records.mdx`'s
      // list and unreachable at /reference/records/. Widen to `**/*.md` if
      // that happens, and check `lib/records.ts`'s `listRecords` (also a
      // flat `readdirSync`) at the same time.
      pattern: '{adr,security}/*.md',
      // Astro's default id algorithm runs each path segment through
      // `github-slugger` (lowercasing `README.md` to `readme`, among other
      // things). This collection's own route-resolution helper
      // (`src/lib/records.ts`'s `recordRouteForRepoPath`) and the remark
      // link rewriter both work from the literal, case-preserved relative
      // path instead — so entry ids are pinned to that same literal form
      // here, rather than relying on two independent implementations of
      // "the same" slugification to never drift apart.
      generateId: ({ entry }) => entry.replace(/\.md$/, ''),
    }),
  }),
};
