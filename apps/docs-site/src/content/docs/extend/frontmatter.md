---
title: Frontmatter contract
description: The frontmatter fields every QAuth docs page sets, and what each one is for.
sidebar:
  order: 1
lastVerified: '2026-07-26'
---

Every page in this docs site's `docs` content collection sets the same frontmatter fields.
The schema for these fields lives in `apps/docs-site/src/content.config.ts`, which extends
Starlight's built-in `docsSchema()` via its `extend` option.

## Fields

| Field           | Required | Meaning                                                                       |
| --------------- | -------- | ----------------------------------------------------------------------------- |
| `title`         | yes      | Page title; also the sidebar label.                                           |
| `description`   | yes      | One sentence; used for the meta description and search.                       |
| `sidebar.order` | yes      | Position within its lane. Pages sort by this value, ascending.                |
| `lastVerified`  | yes      | ISO date (`YYYY-MM-DD`) the page's claims were last checked against the tree. |
| `unbuiltClaims` | no       | Declares that this page intentionally describes something not yet built.      |

`title`, `description`, and `sidebar.order` come from Starlight's own schema. `lastVerified`
and `unbuiltClaims` are added by this project's `extend:` — without that extension, Zod would
silently strip them from frontmatter instead of validating them.

## `lastVerified` is recorded, not enforced

The schema requires every page to _set_ `lastVerified`; a page with no `lastVerified` field
fails the build. What the schema does not do is check whether the date is still accurate. A
staleness threshold — failing CI once a page's `lastVerified` passes some age — would break
unrelated pull requests for a problem they didn't cause, so there isn't one. Instead, the
Reference lane's status page surfaces the oldest `lastVerified` date across the site, so rot is
visible rather than silently accumulating. Do not turn this into a hard gate later: recording
the date and enforcing its freshness are deliberately different jobs.

## The `unbuiltClaims` marker

A guard fails any page that claims a feature is deferred, not implemented, or coming soon when
that feature's module or flag already exists in the tree — the guard's job is to catch
documentation that has drifted behind the code. Two pages legitimately need to describe
something unbuilt anyway: a specification for endpoints that don't exist yet, and honest notes
about a surface that is currently thin. Setting `unbuiltClaims: true` in a page's frontmatter
tells the guard to skip that page.

```yaml
---
title: Example
description: An example of the marker.
sidebar:
  order: 1
lastVerified: '2026-07-26'
unbuiltClaims: true
---
```

This is a narrow, page-level escape hatch for that one specific check, not a general-purpose
way to silence it. Reaching for `unbuiltClaims: true` because a guard failure is inconvenient,
on a page that isn't actually describing something unbuilt, is a defect — file it as one if you
see it.
