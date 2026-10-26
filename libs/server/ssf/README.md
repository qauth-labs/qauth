# @qauth-labs/server-ssf

The protocol of QAuth's Shared Signals Framework transmitter
([OpenID SSF 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html), RFC 8417,
RFC 8935, RFC 9493; issue #410): what the auth server's SSF routes and the delivery role's SSF route
share. It holds no key and opens no connection of its own.

- **Metadata** (`buildTransmitterMetadata`): the `/.well-known/ssf-configuration` document of a
  realm. Push delivery only, OAuth 2.0 access tokens with the `ssf:stream` scope,
  `default_subjects: NONE`. Every URL is built from the realm's issuer. `jwks_uri` names the
  transmitter's own JWKS (`SSF_PATHS.jwks`, `/ssf/jwks.json`), which holds only the SET keys: they
  are kept out of the realm JWKS of the token keys (d-1026-09).
- **Streams** (`streamConfigRequestSchema`, `streamConfiguration`, `checkDelivery`,
  `assertTransmitterMembers`): a receiver's requests and the configuration QAuth returns.
  `events_delivered` is the requested events the transmitter supports; transmitter-supplied members
  in an update must match. The `authorization_header` is never returned.
- **Subjects** (`subjectIdentifierSchema`, `ssfSubjectOf`, `eventSubjectOf`): RFC 9493 identifiers
  and the mapping onto event store subjects. A user is `iss_sub` with the realm's issuer; a client
  is `uri` when its `client_id` is an absolute URI, `opaque` otherwise; a stream is `opaque`.
- **SETs** (`setClaims`, `verificationSetClaims`): `jti` is the event id and `iat` the event's
  time, so a retry repeats both. The signer adds `iss` and the header.
- **The push route** (`createSsfDeliveryRoute`): a `DeliveryRoute` of
  `@qauth-labs/server-event-delivery`. It lists every stream it may deliver to with the event types
  and subjects it takes, signs each SET through the delivery role's signer handle
  (`event_signing`), and POSTs it through the egress client, which checks the endpoint's addresses
  again at every attempt. A paused stream's deliveries are held, spending no attempt. A `400` ends
  a delivery only with a known RFC 8935 `err`. `receiverErrorClass` gives the coarser class a
  receiver reads on its stream status.

Which QAuth event types a stream can receive comes from the registry's `ssf` slot
(`ssfEventsSupported`, `eventTypesFor`). EVT-11 (#540) fills it; until then a stream receives its
verification events only.
