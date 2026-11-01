---
title: SSF transmitter
description: Turn on QAuth's Shared Signals Framework transmitter, register a receiver, and run the verification event end to end.
sidebar:
  order: 11
lastVerified: '2026-11-01'
---

QAuth can be an [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
(SSF) transmitter. A receiver, such as a resource server, creates a stream at QAuth, and QAuth
pushes Security Event Tokens (SETs, RFC 8417) to the receiver's endpoint (RFC 8935). The SETs come
out of QAuth's event store and are sent by the delivery role, with its retries and its delivery
history.

The transmitter is experimental and off by default. It sends QAuth's security events as CAEP 1.0,
RISC 1.0 or QAuth-defined events: a sign-out as `session-revoked`, a withdrawn consent as
`token-claims-change`, a client secret, API key or wallet credential change as
`credential-change`, an RFC 7009 revocation as QAuth's `token-revoked`, and so on.
[SSF events](/reference/ssf-events/) lists every mapping, its subject and its members, generated
from the event registry.

## Turn it on

Two switches, both off by default:

1. The deployment's: `SSF_TRANSMITTER_ENABLED=true`. Off, the server registers no SSF route,
   serves no `/.well-known/ssf-configuration` and writes no SSF delivery.
2. Each realm's: `realms.ssf_transmitter_enabled`. A realm whose switch is off answers `404` on the
   metadata and on every `/ssf/` route, as for a route that does not exist, and its streams receive
   nothing. No API sets it yet; set it on the realm row:

```sql
UPDATE realms SET ssf_transmitter_enabled = true WHERE name = 'master';
```

The auth server reads realm rows through a cache, so a change takes effect within 30 seconds.

A realm needs two keys of its own: an `event_signing` key, which signs its SETs, and a
`data_at_rest` key, which stores receivers' headers. The default realm gets both at boot. For
any other realm, create them before turning its switch on (see
[Keys](/operate/keys/#adding-a-key-auth-serverkeyscreate)):

```bash
pnpm nx run auth-server:keys:create --realm=<realm> --purpose=event_signing --algorithm=EdDSA
pnpm nx run auth-server:keys:create --realm=<realm> --purpose=data_at_rest --algorithm=A256GCM
```

Without them, creating a stream with an `authorization_header` fails, and every delivery fails at
signing until its attempts run out.

With both on, the realm:

- serves the transmitter metadata at `/.well-known/ssf-configuration`. Every URL in it is built
  from the realm's issuer, which is also the `iss` of its SETs;
- serves its SET signing keys (the `event_signing` purpose of ADR-019 Decision 9) at
  `/ssf/jwks.json`, the `jwks_uri` of the metadata. A receiver verifies each SET with a key from
  there. It needs no token, and is cached for at most 5 minutes, as the realm JWKS is;
- keeps the SET keys out of the realm JWKS at `/.well-known/jwks.json`, which holds only the keys
  of its access and ID tokens. A resource server that skips the `typ` check therefore cannot take
  a SET for an access token;
- serves stream management under `/ssf/` (see the
  [API reference](/integrate/api-reference/#shared-signals-framework-transmitter)).

## Register a receiver

A receiver is an OAuth client of the realm. It authenticates with its own access token from the
`client_credentials` grant, and the token must:

- carry the `ssf:stream` scope (a token without it gets `403`);
- name the realm's issuer in `aud`, so a token minted for another resource cannot manage streams;
- name no other realm's issuer in `aud`. A `client_id` is unique only within a realm, so such a
  token may come from a client of the same name in that realm. It gets `401`.

Give `ssf:stream` only to clients you trust with the realm's security events. A receiver may add
a user only when the user is related to it, in one of two ways:

- **Its users.** The user holds an active consent for the receiver's client, or a live refresh
  token the client was issued (decided on 2026-10-26). Such a receiver is the client your users
  sign in through, given `client_credentials` and `ssf:stream` as well, with the
  `client_credentials` grant kept to `ssf:stream` (see below).
- **A resource server's users.** The user holds a live refresh token whose audience names the
  receiver as a resource server (decided on 2026-10-31). A receiver is the resource server of the
  values its `audience` lists, the column introspection reads the same way, except a
  `urn:qauth:aud:` value and the realm's issuer: every receiver lists the issuer to manage its
  stream, and the issuer names QAuth itself. A refresh token's audience is what the refresh grant
  gives its access tokens: its RFC 8707 `resource` when it has one, else its client's `audience`,
  else its client's `client_id`.

A refresh token is live as the token endpoint reads it: not revoked, not expired, and its family
not past the realm's `sso_max_lifespan` or the browser session that started it. A disabled user is
related to no receiver, and a client that no user signs in to and that serves no audience can add
no user.

Two grants relate no one. QAuth stores no access token, so a user who holds only access tokens for
a resource server, issued without a refresh token (the user approved without remembering the
decision, so no consent was stored), is not related to it. And a consent's per-resource scopes
(`resource_scopes`) record a grant, not a token: they relate no user to a resource server.

A user subject lasts as long as its relation. The relation is checked when the subject is added,
and again by the `ssf-subject-sweep` job every hour: once the relation has ended (the user
withdrew the consent, the refresh tokens were revoked or ran out, or the user was disabled or
deleted) and every event about the user has reached the stream (delivered, or given up after its
attempts), the job deletes the subject. So the SET that tells of the end, a withdrawn consent's
`token-claims-change` say, still reaches the receiver, and none after it does. The receiver adds
the user again once they are related again. A disablement ends the relation too: after
`account-disabled` reaches the stream the sweep deletes the subject, so `account-enabled` reaches
only a stream the sweep has not cleared yet, and the receiver adds the user again once they are
enabled.

A receiver may add any client of the realm, but a client's own credential changes (its secret, its
API keys) reach only that client's stream. Taking the scope away, disabling or suspending the
client, or deleting it stops its deliveries, and its token stops working on `/ssf/` at once, not
when it expires; deleting the client deletes its stream.

Give the relying party's client `client_credentials`, the `ssf:stream` scope and the realm's issuer
as its audience, beside what its users sign in with, and keep the `client_credentials` grant to
`ssf:stream` with `client_credentials_scopes`, for example as an entry of the seed manifest's
`clients`:

```json
{
  "client_id": "notes-app",
  "name": "Notes",
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
  "redirect_uris": ["https://notes.example.com/callback"],
  "scopes": ["openid", "notes:read", "ssf:stream"],
  "client_credentials_scopes": ["ssf:stream"],
  "audience": ["https://auth.example.com"]
}
```

A `client_credentials` token names no user: its `sub` is the client's `client_id`.
`client_credentials_scopes` lists the scopes that grant may issue, out of `scopes`. With
`["ssf:stream"]`, the client gets a token of its own for `ssf:stream` only, and the scopes its
users grant it at sign-in, `openid` and `notes:read` here, reach only the tokens a user granted:
a `client_credentials` request for one of them is refused with `invalid_scope`. The seeder refuses
a list that names a scope `scopes` does not hold, and the list on a client without the
`client_credentials` grant.

The receiver then gets a token:

```bash
curl -s https://auth.example.com/oauth/token \
  -d grant_type=client_credentials -d scope=ssf:stream \
  -d client_id=notes-app -d client_secret="$SECRET"
```

:::caution[Without the list, the client gets a token without a user for any of its scopes]
A client that holds `client_credentials` and has no `client_credentials_scopes` gets a token for
itself, with no user, for any scope in its `scopes`, each scope its users grant it at sign-in
included. Set the list on every client that signs users in and holds `client_credentials`.

Add it to the client's manifest entry. The seeder writes an existing client only with `--rotate`,
which also issues it a new secret; to set the stored row without rotating:

```sql
UPDATE oauth_clients SET client_credentials_scopes = '["ssf:stream"]'
WHERE realm_id = '<realm id>' AND client_id = 'notes-app';
```

A later `--rotate` refuses an entry without the list for a client whose row has one, so the
rotation cannot lift it unnoticed; to lift it on purpose, set the column to `NULL` first.

The token endpoint reads the client row on every request, so the next token request follows the
list, on every node of a release that knows it (a node of an older release ignores the column).
A token issued before keeps its scopes until it expires.
:::

## Create a stream

A receiver has one stream per realm; a second create answers `409`. Delivery is push only, to an
`https` URL on a public address:

```bash
curl -s https://auth.example.com/ssf/stream \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "events_requested": [
      "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
      "https://schemas.openid.net/secevent/caep/event-type/credential-change"
    ],
    "delivery": {
      "method": "urn:ietf:rfc:8935",
      "endpoint_url": "https://risk.example.com/ssf/events",
      "authorization_header": "Bearer receiver-shared-secret"
    },
    "description": "Risk engine"
  }'
```

- QAuth checks `endpoint_url` through its egress client when the stream is created or changed: an
  address that is private, loopback, link-local or otherwise not public is refused with `400`
  (`bad_request`, with `endpoint_url is refused` as the `detail`; the reason is in the server's
  log, not in the answer). It checks again at every delivery, so a name that later resolves to
  such an address is refused then too.
- `authorization_header` is sent with every push. QAuth stores it encrypted with the realm's
  `data_at_rest` key and never returns it. A `PATCH` whose `delivery` leaves it out and keeps the
  same `endpoint_url` keeps the stored header, so sending back what a read returned changes
  nothing; a new `endpoint_url` never gets the old header, and a `PUT` replaces it.
- `events_delivered` in the answer is what QAuth will send: the requested events it supports.
  `events_supported` lists them all.

## Add subjects

The transmitter's `default_subjects` is `NONE`: a stream receives events only about the subjects
its receiver adds. Name a user of the realm as `iss_sub` with the realm's issuer, and a client by
its `client_id`, as `uri` when that is a URL and `opaque` otherwise. A user must be related to the
receiver, as above; any other user, and a user id that does not exist, is refused with
`403` (`forbidden`), as SSF 1.0 §8.1.3.2 prescribes for a subject the receiver may not add:

```bash
curl -s https://auth.example.com/ssf/subjects/add \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"stream_id": "'"$STREAM"'", "subject": {"format": "iss_sub", "iss": "https://auth.example.com", "sub": "'"$USER_ID"'"}}'
```

A user's id is a UUID, and QAuth keeps it in lower case, as its SETs name the user: an upper-case
spelling is the same subject. A subject in another format, or with another issuer, is kept as sent
and matches no event. A stream holds at most 1000 subjects.

Some events reach fewer streams than the subject alone would say. A withdrawn consent, an RFC 7009
revocation and a replay's family revocation tell of the user's dealings with one client, and a
client secret or API key change is about one client's credentials, so only that client's stream
receives them. An emergency key retirement reaches every stream of the realm that requested it.

A replay is sent only when it revoked refresh tokens. An authorization code redeemed a second time
whose first redemption issued no refresh token (the user approved without remembering the
decision, so no consent was stored, say) revokes no family: QAuth still puts the access tokens the
code issued on the denylist, so introspection answers `active: false` for them, but no stream
receives a SET. Nor does one for a refresh token presented again after its family was revoked
already.

## Run the verification event

```bash
curl -s https://auth.example.com/ssf/verify \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"stream_id": "'"$STREAM"'", "state": "check-1"}'
```

QAuth answers `204`, records the request as a `ssf.stream.verification_requested` event, and the
delivery role POSTs a SET to the stream's endpoint with `Content-Type: application/secevent+jwt`:

```json
{
  "iss": "https://auth.example.com",
  "jti": "0199f2b4-2b3c-7d4e-9f5a-6b7c8d9e0f1a",
  "iat": 1792927942,
  "aud": "risk-engine",
  "sub_id": { "format": "opaque", "id": "<stream_id>" },
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/verification": { "state": "check-1" }
  }
}
```

The header names the signing key (`kid`) and `typ: secevent+jwt`. The `jti` is the event's id,
and a retry sends the same SET, so the receiver drops a duplicate by its `jti`. A second
verification request from the same receiver within 10 seconds (`min_verification_interval`)
answers `429`, even for a stream it deleted and created again.

## Errors

SSF 1.0 gives stream management statuses but no error body, so QAuth answers every refusal on
`/ssf/` and on the metadata the way it answers on every route that is not an OAuth protocol
endpoint: an RFC 9457 problem document, `application/problem+json`, with a stable `code` and the
`trace_id` the server logged the request under ([Problem types](/reference/problem-types/)).
Branch on the status and `code`, never on `detail`:

| Status | `code`                 | When                                                                                            |
| ------ | ---------------------- | ----------------------------------------------------------------------------------------------- |
| `400`  | `validation_error`     | The body or the query does not match the schema; `errors` names each field.                     |
| `400`  | `bad_request`          | The protocol refuses the request: poll delivery, a refused `endpoint_url`, a mismatched member. |
| `401`  | `unauthorized`         | The request carries no access token.                                                            |
| `401`  | `invalid_access_token` | The token is not valid, not the receiver's own, or for another audience or realm.               |
| `401`  | `access_token_expired` | The token has expired.                                                                          |
| `403`  | `forbidden`            | The token lacks `ssf:stream`, or the receiver may not add the user it named as a subject.       |
| `404`  | `not_found`            | No such stream for this receiver, or a realm that does not run the transmitter.                 |
| `409`  | `conflict`             | The receiver already has a stream in the realm.                                                 |
| `429`  | `too_many_requests`    | A verification within `min_verification_interval`; `Retry-After` says when to try again.        |

A `401` for a token that was presented carries
`WWW-Authenticate: Bearer realm="OAuth", error="invalid_token"`; one for a request with no token
carries `Bearer realm="OAuth"` alone (RFC 6750 §3.1). A `403` for a token without the scope
carries `error="insufficient_scope", scope="ssf:stream"` (RFC 6750 §3); one for a user the
receiver may not add carries `Bearer realm="OAuth"` alone, since no other token would let it
through. A realm that does not run the transmitter answers exactly what a path no route serves
answers.

## Watch deliveries

`GET /ssf/status?stream_id=…` returns the stream's status and, as QAuth's extension,
`delivery_status`: the deliveries still pending and the latest failed attempt.

```json
{
  "stream_id": "…",
  "status": "enabled",
  "delivery_status": {
    "pending": 1,
    "last_failure": {
      "event_id": "…",
      "attempts": 1,
      "status_code": 503,
      "error": "http_status",
      "time": "2026-10-25T10:00:01.000Z",
      "state": "retrying",
      "next_attempt_at": "2026-10-25T10:00:31.000Z"
    }
  }
}
```

A push is delivered when the receiver answers `2xx`. Any other answer, a timeout or a network
failure is retried on the delivery role's schedule (`EVENT_DELIVERY_*`), except a `400` with an
RFC 8935 `err` that says the SET itself is wrong (`invalid_request`, `invalid_issuer`,
`invalid_audience`, `invalid_state`), which ends the delivery. A `400` without a known `err`,
such as a proxy's error page, is retried. Attempts are counted in
`qauth_events_delivery_attempts_total{kind="ssf"}` (see [observability](/operate/observability/)).

`error` is the class of the failed attempt. An endpoint QAuth refused to reach (a private
address) and one it could not reach both read `destination_unreachable`, so the status does not
tell a receiver which names resolve to private addresses. The delivery history and the server's
log keep the exact class (`destination_blocked` or `network`).

`POST /ssf/status` sets the status. `paused` holds the stream's events, however long the pause.
Holding spends no attempt and records no failure: the delivery role looks at a held delivery
every 30 seconds, and sends it at the first look after the stream is `enabled` again. `disabled`
holds nothing. Deleting the stream ends its pending deliveries without sending them.

A held or retried delivery is sent as the stream is at that attempt, not as it was when the event
was queued: an event the receiver no longer requests, or about a subject it has removed since,
is not sent, and the delivery ends.

A held delivery is pending, so it holds back [event retention](/operate/observability/) as any
pending delivery does: no event of the realm from the oldest held one on is deleted. Disable or
delete a stream rather than leave it paused for good.

## Turning it off

Turning the realm's switch off stops its deliveries: each pending one ends at its next attempt.
Turning `SSF_TRANSMITTER_ENABLED` off leaves pending SSF deliveries in the queue, unsent. They
no longer hold back [event retention](/operate/observability/): with the switch off no node
serves SSF, so retention deletes their events at the realm's retention like any other, and the
deliveries go with them. A delivery whose event is still there when the switch is on again is
sent then. Set the switch the same on every node: a node with it off does not count SSF
deliveries for retention.

## In a distributed deployment

The delivery role reads the streams, the event subject each stream subject stands for, and the
columns that say whether a stream may receive events: `eventDeliveryGrantStatements()` in
`@qauth-labs/infra-db` grants them. It cannot read a subject as the receiver sent it, which may be
an email address or a phone number. It decrypts a receiver's `authorization_header` through the
signer as the `delivery` caller, which may decrypt but never encrypt; it holds no key.
