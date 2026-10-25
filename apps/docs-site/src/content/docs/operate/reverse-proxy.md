---
title: Reverse Proxy
description: The rules a reverse proxy in front of QAuth follows, proxy-neutrally, and the reference nginx configuration in deploy/reference/proxy that implements them.
sidebar:
  order: 10
lastVerified: '2026-10-25'
---

QAuth runs behind a reverse proxy ([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
Decisions 1, 5 and 8). The proxy terminates TLS, sends each realm host to the auth server, sends
`/ui/*` on the same host to the ceremony app, and sets the security headers of the ceremony pages.

The repository ships a reference configuration for nginx in `deploy/reference/proxy/`. The rules
below do not depend on nginx: another proxy that follows every one of them is a valid replacement.

:::caution[The ceremony app has not shipped yet]
Until the reference ceremony app ships, the auth server renders `/ui/*` itself and needs its
session cookie there. This configuration strips that cookie and sends `/ui/*` to the ceremony app,
so it is not yet a working front for browser sign-in. It fixes and tests the rules ahead of that
split.
:::

## The rules

1. **Realm hosts only.** Every realm's host goes to the auth server. The match is case-insensitive
   and ignores the port. Any other host gets `421 Misdirected Request`, with no realm context. Only
   `/health` and `/ready` answer on every host. They go to the auth server, which today serves
   `/health` only.
2. **Route on the normalised path.** Merge repeated slashes, decode the percent-escapes of
   unreserved characters, and resolve `.` and `..` segments. Then match case-sensitively. Send the
   upstream the normalised path, not the raw request target, so it cannot read the path
   differently from the way it was routed. A proxy may decode more than that: nginx decodes every
   escape, so `%3B` reaches the upstream as `;`. Rules 3 and 9 then apply to the decoded path.
3. **Refuse path variants with 404.** The proxy answers by itself and neither upstream sees the
   request:
   - a disguised separator anywhere in the path, before the query: an encoded slash (`%2F`), or a
     backslash (`\` or `%5C`), which a WHATWG URL parser reads as a slash;
   - a path that looks like `/ui` but does not start with exactly `/ui/`. That is any path which,
     with every percent-escape decoded and compared case-insensitively, matches
     `^/ui(?:$|[^a-z0-9_-])`. Examples: `/ui` itself, a case variant such as `/UI/login`, a path
     parameter such as `/ui;x/login` or `/ui%3Bx/login`.
4. **Split by path.** `/ui/*` goes to the ceremony app. Every other path goes to the auth server.
5. **Strip cookies from `/ui/*`.** Remove the `Cookie` header from every request to `/ui/*`,
   including every separate `cookie` field of an HTTP/2 request. The ceremony app never sees
   QAuth's cookies, so it can neither read nor mint a session-bound value.
6. **Set the ceremony headers.** On every `/ui/*` answer, replace whatever the app sent. This
   includes error answers and answers the proxy makes itself, such as a `502`.
   - `Content-Security-Policy: default-src 'self'; base-uri 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'`
   - `Referrer-Policy: no-referrer`
   - `Cache-Control: no-store`, with one exception. A content-hashed asset gets
     `Cache-Control: public, max-age=31536000, immutable` when all of these hold: the answer is a
     `200` or `304` to a `GET` or `HEAD`, it sets no cookie, and the whole normalised path matches
     `^/ui/assets/(?:[A-Za-z0-9._-]+-)?[A-Za-z0-9_-]{8,}\.(?:js|mjs|css|woff2|woff|svg|png|jpg|jpeg|gif|webp|avif|ico)\z`.
     The pattern ends in `\z`, not `$`, because in most regular-expression engines `$` also
     matches before a final newline, which `%0A` decodes to.
7. **Let no upstream steer the proxy.** Ignore every response header that asks the proxy to fetch
   another location or file internally: nginx's `X-Accel-Redirect` and the other `X-Accel-*`
   headers, or their equivalent in another proxy. Otherwise the ceremony app could have the proxy
   fetch an auth server page, with the client's cookies, and serve it under `/ui/*` without the
   ceremony headers.
8. **Overwrite the forwarded headers.** Set `X-Forwarded-For` to the address the proxy accepted the
   connection from, `X-Forwarded-Host` to the realm host and `X-Forwarded-Proto` to the scheme the
   client used, which is `https` on the only listener. Never pass on, or append to, what the
   client sent. Remove `Forwarded`, `X-Real-IP`, `X-Forwarded-Port`, `X-Forwarded-Prefix`,
   `X-Original-URL` and `X-Rewrite-URL`: QAuth reads none of them, and a web framework behind the
   proxy might. Then set the auth server's `TRUST_PROXY` to the proxy's address, so the auth server
   believes these headers from the proxy and from no one else.
9. **Keep internal paths internal.** Answer `404` on the public side for `/metrics`, `/internal/*`
   and their variants: every path which, with every percent-escape decoded and compared
   case-insensitively, matches `^/(?:metrics|internal)(?:$|[^a-z0-9_-])`.
10. **Mount certificates as files.** Automatic certificates (ACME) are not part of 1.0.

## The reference configuration

| File                       | Edit it? | What it holds                                                                                                              |
| -------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------- |
| `nginx.conf`               | No       | The `http` block: path normalisation, the separator and `Cache-Control` maps, and the default server (421, health).        |
| `qauth/realm.conf`         | No       | The rules of a realm host: path variants, internal paths, `/ui/*` and its headers, and everything else to the auth server. |
| `qauth/proxy-headers.conf` | No       | `Host`, the forwarded headers and the ignored `X-Accel-*` headers, for every proxied location.                             |
| `site/upstreams.conf`      | Yes      | The addresses of the auth server and the ceremony app.                                                                     |
| `site/realms.conf`         | Yes      | The realm hosts and their certificate paths. The hosts in it are examples.                                                 |
| `test/`                    | No       | The CI test and its stub upstream.                                                                                         |

Inside the container the files sit at `/etc/nginx/nginx.conf`, `/etc/nginx/qauth/` and
`/etc/nginx/site/`. The certificate and its key are mounted at `/etc/nginx/certs/fullchain.pem`
and `/etc/nginx/certs/privkey.pem`. One certificate covers every realm host, and the default server
presents it too. For a certificate per host, copy the server block in `site/realms.conf` once per
host, with that host's `server_name` and certificate paths, and keep its `include`.

`site/realms.conf` names realm hosts only. An endpoint host, which server-to-server callers use
(Decision 1), usually stays on the internal network; through this proxy it gets `421`.

nginx resolves the upstream names once, at start, so the auth server and the ceremony app must be
resolvable when the proxy starts.

With the Compose stack, the proxy joins `qauth-network` with a fixed address below `<prefix>.128`,
as [Docker](/operate/docker/#production-considerations) describes for `TRUST_PROXY`:

```yaml
services:
  reverse-proxy:
    image: nginx:1.30-alpine
    ports:
      - '443:443'
    volumes:
      - ./deploy/reference/proxy/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./deploy/reference/proxy/qauth:/etc/nginx/qauth:ro
      - ./proxy/site:/etc/nginx/site:ro # your copies of site/*.conf
      - ./proxy/certs:/etc/nginx/certs:ro # fullchain.pem and privkey.pem
    networks:
      qauth-network:
        ipv4_address: ${QAUTH_NETWORK_PREFIX:-172.30.80}.20
```

Then set `TRUST_PROXY=172.30.80.10,172.30.80.20` on the auth server: the developer portal's address
and the proxy's.

The reference configuration leaves out a plain-HTTP listener and its redirect, IPv6 listeners, and
a hosted bot-challenge provider's script hosts. ADR-019 Decision 5 lets an operator add those
hosts to the policy of the sign-up and sign-in pages only; by default there are none.

## The test

`pnpm nx run reference-proxy:test-integration` starts the configuration, unchanged, in the nginx
image, in front of a stub auth server and a stub ceremony app. The stubs echo the headers and
cookies they receive, and the test checks every rule above against them, including that a refused
request reaches neither stub. It needs Docker and `openssl`. CI's `integration` job runs it
whenever a file under `deploy/reference/proxy/` changes.
