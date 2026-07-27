---
title: Extend
description: Guides for contributing to QAuth itself.
sidebar:
  order: 0
lastVerified: '2026-07-26'
---

This lane is for contributors working on QAuth itself.

If you are about to change the codebase, read these in order:

1. [Repository map](/extend/repo-map/) — the `apps/` and `libs/` layout, the Nx scope tags that
   decide where new code may live, and the Windows CRLF gotcha worth knowing on day one.
2. [Request lifecycle](/extend/architecture/) — how `apps/auth-server` boots, which registration
   orders are load-bearing, and the two security invariants a change can silently undo.
3. [Testing](/extend/testing/) — the tiers, what each one cannot catch, and the caching failures
   this repo has already had.
4. [Adding a credential provider](/extend/adding-a-credential-provider/) — the ADR-003 extension
   point, which is the main way this server is meant to grow.

[Frontmatter contract](/extend/frontmatter/) covers this documentation site itself; read it before
adding a page.
