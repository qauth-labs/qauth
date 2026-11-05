# Reference reverse proxy

The reference nginx configuration for QAuth (ADR-019 Decisions 1, 5 and 8). It routes every realm
host to the auth server and `/ui/*` on the same host to the ceremony app, strips QAuth's cookies
there, sets the ceremony pages' security headers, overwrites the forwarded headers, answers 421 for
any other host and 404 for `/metrics` and `/internal/*`.

The rules, the file layout and how to run it are in the operator docs:
[Reverse Proxy](https://docs.qauth.dev/operate/reverse-proxy/)
(`apps/docs-site/src/content/docs/operate/reverse-proxy.md`).

- `nginx.conf` and `qauth/` are QAuth's rules. Do not edit them.
- `site/` holds the three files you edit: the upstream addresses, the realm hosts and a hosted bot
  challenge's script hosts (empty by default).
- `test/` runs this configuration, unchanged, in front of stub upstreams:
  `pnpm nx run reference-proxy:test-integration` (needs Docker and `openssl`).
