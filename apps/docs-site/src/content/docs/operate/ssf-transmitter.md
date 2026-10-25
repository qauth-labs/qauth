---
title: SSF transmitter
description: Turn on QAuth's Shared Signals Framework transmitter, register a receiver, and run the verification event end to end.
sidebar:
  order: 11
lastVerified: '2026-10-25'
---

QAuth can be an [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
(SSF) transmitter. A receiver, such as a resource server, creates a stream at QAuth, and QAuth
pushes Security Event Tokens (SETs, RFC 8417) to the receiver's endpoint (RFC 8935). The SETs come
out of QAuth's event store and are sent by the delivery role, with its retries and its delivery
history.

The transmitter is experimental and off by default. Today it sends the verification event only:
the mapping of QAuth's security events to CAEP and RISC events comes with #540.

## Turn it on

Two switches, both off by default:

1. The deployment's: `SSF_TRANSMITTER_ENABLED=true`. Off, the server registers no SSF route,
   serves no `/.well-known/ssf-configuration`, keeps its JWKS as it was and writes no SSF
   delivery.
2. Each realm's: `realms.ssf_transmitter_enabled`. A realm whose switch is off answers `404` on the
   metadata and on every `/ssf/` route, and its streams receive nothing. No API sets it yet; set it
   on the realm row:

```sql
UPDATE realms SET ssf_transmitter_enabled = true WHERE name = 'master';
```

The auth server reads realm rows through a cache, so a change takes effect within 30 seconds.

With both on, the realm:

- serves the transmitter metadata at `/.well-known/ssf-configuration`. Every URL in it is built
  from the realm's issuer, which is also the `iss` of its SETs;
- adds its SET signing keys (the `event_signing` purpose of ADR-019 Decision 9) to
  `/.well-known/jwks.json`. A receiver verifies each SET with a key from there;
- serves stream management under `/ssf/` (see the
  [API reference](/integrate/api-reference/#shared-signals-framework-transmitter)).

## Register a receiver

A receiver is an OAuth client of the realm. It authenticates with its own access token from the
`client_credentials` grant, and the token must:

- carry the `ssf:stream` scope;
- name the realm's issuer in `aud`, so a token minted for another resource cannot manage streams.

Create the client with `client_credentials`, the `ssf:stream` scope and the realm's issuer as its
audience, for example as an entry of the seed manifest's `clients`:

```json
{
  "client_id": "risk-engine",
  "name": "Risk engine (SSF receiver)",
  "grant_types": ["client_credentials"],
  "scopes": ["ssf:stream"],
  "audience": ["https://auth.example.com"]
}
```

The receiver then gets a token:

```bash
curl -s https://auth.example.com/oauth/token \
  -d grant_type=client_credentials -d scope=ssf:stream \
  -d client_id=risk-engine -d client_secret="$SECRET"
```

## Create a stream

A receiver has one stream per realm; a second create answers `409`. Delivery is push only, to an
`https` URL on a public address:

```bash
curl -s https://auth.example.com/ssf/stream \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "events_requested": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
    "delivery": {
      "method": "urn:ietf:rfc:8935",
      "endpoint_url": "https://risk.example.com/ssf/events",
      "authorization_header": "Bearer receiver-shared-secret"
    },
    "description": "Risk engine"
  }'
```

- QAuth checks `endpoint_url` through its egress client when the stream is created or changed: an
  address that is private, loopback, link-local or otherwise not public is refused with `400`. It
  checks again at every delivery, so a name that later resolves to such an address is refused
  then too.
- `authorization_header` is sent with every push. QAuth stores it encrypted with the realm's
  `data_at_rest` key and never returns it.
- `events_delivered` in the answer is what QAuth will send: the requested events it supports.

## Add subjects

The transmitter's `default_subjects` is `NONE`: a stream receives events only about the subjects
its receiver adds. Name a user of the realm as `iss_sub` with the realm's issuer, and a client by
its `client_id`, as `uri` when that is a URL and `opaque` otherwise:

```bash
curl -s https://auth.example.com/ssf/subjects/add \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"stream_id": "'"$STREAM"'", "subject": {"format": "iss_sub", "iss": "https://auth.example.com", "sub": "'"$USER_ID"'"}}'
```

A subject in another format, or with another issuer, is kept and matches no event. A stream holds
at most 1000 subjects.

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
verification request within 10 seconds (`min_verification_interval`) answers `429`.

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
`invalid_audience`, `invalid_state`), which ends the delivery. Attempts are counted in
`qauth_events_delivery_attempts_total{kind="ssf"}` (see [observability](/operate/observability/)).

`POST /ssf/status` sets the status. `paused` holds the stream's events and sends them once it is
`enabled` again, until their attempts run out; `disabled` holds nothing. Deleting the stream ends
its pending deliveries without sending them.

## Turning it off

Turning the realm's switch off stops its deliveries: each pending one ends at its next attempt.
Turning `SSF_TRANSMITTER_ENABLED` off leaves pending SSF deliveries in the queue, unsent, and they
hold back the [event retention](/operate/observability/) of their events until the switch is on
again. Delete the streams first, or turn the realms' switches off and let their deliveries end,
before turning the deployment's switch off.

## In a distributed deployment

The delivery role reads the stream tables and the columns that say whether a stream may receive
events: `eventDeliveryGrantStatements()` in `@qauth-labs/infra-db` grants them. It decrypts a
receiver's `authorization_header` through the signer as the `delivery` caller, which may decrypt
but never encrypt; it holds no key.
