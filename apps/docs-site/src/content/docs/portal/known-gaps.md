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

## `/consents` exists but nothing links to it

`/consents` (`apps/developer-portal/src/routes/consents.tsx`) is a working page — see the
[portal guide](/portal/guide/#the-consents-page) for what it does and a separate authentication
issue on that page. Structurally, it also sits outside the authenticated layout: every other page
a signed-in developer uses lives under `_authed` (`apps/developer-portal/src/routes/_authed.tsx`),
which redirects to `/login` when there is no session. That layout's header renders **no navigation
links at all** — it carries only the product label, the signed-in address and a log-out button. The
one "Manage clients" link in the product is a card on `/dashboard`, not a nav item. `/consents` defines its own top-level route
(`apps/developer-portal/src/routes/consents.tsx:20`) with none of that — no auth redirect, no nav
link. Nothing in the dashboard, the authed header, or any other route links to `/consents`. A
developer reaches it only by typing the URL.

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
