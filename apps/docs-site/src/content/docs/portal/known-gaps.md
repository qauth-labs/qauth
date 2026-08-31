---
title: Known gaps
description: An honest account of where the developer portal is thinner than it looks — a dashboard card that misreports a shipped feature, and a page nothing links to.
sidebar:
  order: 2
lastVerified: '2026-07-27'
unbuiltClaims: true
---

This page documents surfaces in `apps/developer-portal` where the UI is misleading or
incomplete as written today. It exists so the next round of work has an honest baseline rather
than a guess. No dates are implied for any fix below — none has been scheduled.

## The dashboard misreports a shipped feature as unbuilt

`/dashboard` (`apps/developer-portal/src/routes/_authed/dashboard.tsx`) is a 48-line component: a
welcome heading (`apps/developer-portal/src/routes/_authed/dashboard.tsx:15`) and two cards
(`apps/developer-portal/src/routes/_authed/dashboard.tsx:19`). The first card links to client
management. The second reads:

> Coming soon in Phase 2.3.
> — `apps/developer-portal/src/routes/_authed/dashboard.tsx:42`

for **API Keys**. That is not accurate. Static developer API keys shipped — backend in issue #97,
portal UI in issue #98 — and the feature is reachable today: `apps/auth-server/src/app/routes/clients/api-keys.ts`
implements the endpoints, and `apps/developer-portal/src/components/api-keys-section.tsx` is a
full create/list/revoke UI for them, embedded in the client-detail page
(`apps/developer-portal/src/routes/_authed/clients.$clientId.tsx`). See the
[portal guide](/portal/guide/#api-keys) for the working flow.

The dashboard card was never updated after #97/#98 landed. A developer who trusts the dashboard's
own words has no way to discover that API keys already work — the card actively tells them the
opposite of what the rest of the app does.

## ~~`/consents` exists but nothing links to it~~ — fixed

**Resolved in #366.** The consent screen now lives under the authenticated layout
(`apps/developer-portal/src/routes/_authed/consents.tsx`), so it redirects to `/login` without a
session, and the `_authed` header carries a nav link to it
(`apps/developer-portal/src/routes/_authed.tsx`). It also no longer calls the auth-server from the
browser — the separate authentication defect recorded here previously — and it has a test, which
it did not when this gap was written. See the
[portal guide](/portal/guide/#the-consents-page).

Both halves of this gap had the same root cause: no link and no test meant nothing exercised the
page, so its `401` for every portal-authenticated developer went unnoticed.

## Two smaller, verified leftovers

Neither of these is load-bearing, but both are easy to check and both are still scaffold from the
TanStack Start template rather than portal-specific content:

- The document `<title>` is still the framework default:
  `title: 'TanStack Start Starter'` (`apps/developer-portal/src/routes/__root.tsx:18`). Every
  browser tab for this app reads "TanStack Start Starter," not anything naming QAuth.
- The portal's root route, `/`, renders a single unlabelled placeholder:
  `return <Button variant="link">Click me</Button>;`
  (`apps/developer-portal/src/routes/index.tsx:9`). It has no `onClick` handler and does nothing.
  There is no redirect from `/` to `/login` or `/dashboard`, so this is what a browser visiting
  the portal's bare origin actually shows.

## See also

- [Portal guide](/portal/guide/) — what the portal does today, session model included.
