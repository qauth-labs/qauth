import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
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
        // describes something not yet built, so Task 3's unbuilt-claim
        // guard skips it. A narrow, page-level escape hatch — not
        // general-purpose suppression. See extend/frontmatter.md.
        unbuiltClaims: z.boolean().default(false),
      }),
    }),
  }),
};
