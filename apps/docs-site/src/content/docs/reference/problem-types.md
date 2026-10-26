---
title: Problem types
description: Every problem type, code and status a QAuth route that is not an OAuth protocol endpoint answers an error with.
sidebar:
  order: 3
lastVerified: '2026-10-25'
---

Every route that is not an OAuth protocol endpoint answers an error with an RFC 9457 problem
details document ([API conventions → Errors](/reference/api-conventions/#errors)). This page lists
the problem types. A document's `type` is this page's address followed by the type's slug:

```text
https://docs.qauth.dev/reference/problem-types/#validation-error
```

Each type has one `code` and one `title`, and each code is sent with the status listed under it,
except two: `bad_request` is also sent with any other 4xx status that has no code of its own (such
as 406), and `internal_error` with any other 5xx (such as 502 or 504). A client branches on `code`
and the status, never on `type`, `title` or `detail`. The codes and the slugs are inside the 1.0
promise ([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)): each keeps its meaning
within a major version, and a minor release may add types. A client treats a code it does not know
by its HTTP status.

An error the server cannot place more precisely gets the type of its status: `bad-request`,
`unauthorized`, `forbidden`, `not-found` and so on. A 5xx never carries a `detail`; its `trace_id`
finds the failure in the server log.

The list is generated from `PROBLEM_CODES` in
`apps/auth-server/src/app/api-conventions/problem.ts`, and a test fails when the two differ. Which
type each domain error class answers is set once, in
`apps/auth-server/src/app/api-conventions/error-classes.ts`: the classes of
`@qauth-labs/shared-errors`, and those a route or a server library defines itself. The Shared
Signals Framework transmitter's routes answer `bad-request`, `validation-error`, `unauthorized`,
`invalid-access-token`, `access-token-expired`, `forbidden`, `not-found`, `conflict` and
`too-many-requests`. A request with no credentials answers `unauthorized`, whether the route takes
an access token or the session cookie; a token that was presented and refused answers
`invalid-access-token` or `access-token-expired`.

## `bad-request`

**Code** `bad_request` · **Status** 400 · **Title** Bad request

The request is malformed and no more specific code applies. Also sent with any other 4xx status that has no code of its own.

## `validation-error`

**Code** `validation_error` · **Status** 400 · **Title** Validation error

The request does not match the schema of the operation. `errors` names each field.

## `invalid-request`

**Code** `invalid_request` · **Status** 400 · **Title** Invalid request

A parameter of an OAuth or OpenID request is missing, repeated or not valid (RFC 6749 §5.2).

## `invalid-scope`

**Code** `invalid_scope` · **Status** 400 · **Title** Invalid scope

A requested scope is unknown, malformed or not allowed (RFC 6749 §5.2).

## `invalid-grant`

**Code** `invalid_grant` · **Status** 400 · **Title** Invalid grant

An authorization grant or refresh token is not valid, has expired or was issued to another client (RFC 6749 §5.2).

## `invalid-target`

**Code** `invalid_target` · **Status** 400 · **Title** Invalid target

A requested `resource` is not one the grant allows (RFC 8707 §2.2).

## `unauthorized-client`

**Code** `unauthorized_client` · **Status** 400 · **Title** Unauthorized client

The client may not use this grant or this response type (RFC 6749 §5.2).

## `unsupported-grant-type`

**Code** `unsupported_grant_type` · **Status** 400 · **Title** Unsupported grant type

The server does not support the `grant_type` (RFC 6749 §5.2).

## `invalid-client-metadata`

**Code** `invalid_client_metadata` · **Status** 400 · **Title** Invalid client metadata

A client metadata value is not valid or not allowed (RFC 7591 §3.2.2).

## `invalid-redirect-uri`

**Code** `invalid_redirect_uri` · **Status** 400 · **Title** Invalid redirect URI

A redirect URI is not valid or not allowed (RFC 7591 §3.2.2).

## `invalid-cursor`

**Code** `invalid_cursor` · **Status** 400 · **Title** Invalid cursor

The `cursor` does not parse, or it belongs to another list.

## `invalid-verification-token`

**Code** `invalid_verification_token` · **Status** 400 · **Title** Invalid verification token

The email verification token in the request is not valid, or has expired.

## `invalid-csrf-token`

**Code** `invalid_csrf_token` · **Status** 400 · **Title** Invalid CSRF token

A cookie-authenticated request that changes state carries no CSRF token, or not the browser session's.

## `unauthorized`

**Code** `unauthorized` · **Status** 401 · **Title** Unauthorized

The request carries no credentials: no access token on a route that takes one, or no valid browser session on a route that takes the session cookie.

## `access-token-expired`

**Code** `access_token_expired` · **Status** 401 · **Title** Access token expired

The access token has expired.

## `invalid-access-token`

**Code** `invalid_access_token` · **Status** 401 · **Title** Invalid access token

The access token is not valid, is not valid for this operation, or names no active user.

## `invalid-credentials`

**Code** `invalid_credentials` · **Status** 401 · **Title** Invalid credentials

The identifier or the credential is wrong. The answer does not say which.

## `invalid-client`

**Code** `invalid_client` · **Status** 401 · **Title** Invalid client

Client authentication failed (RFC 6749 §5.2).

## `invalid-dpop-proof`

**Code** `invalid_dpop_proof` · **Status** 401 · **Title** Invalid DPoP proof

The DPoP proof is missing or not valid for this request (RFC 9449 §7.1).

## `forbidden`

**Code** `forbidden` · **Status** 403 · **Title** Forbidden

The caller is authenticated but may not perform the operation.

## `email-not-verified`

**Code** `email_not_verified` · **Status** 403 · **Title** Email address not verified

The account must verify its email address first.

## `not-found`

**Code** `not_found` · **Status** 404 · **Title** Not found

The resource does not exist, or the caller may not know that it exists.

## `method-not-allowed`

**Code** `method_not_allowed` · **Status** 405 · **Title** Method not allowed

The resource does not support the method.

## `conflict`

**Code** `conflict` · **Status** 409 · **Title** Conflict

The request conflicts with the current state of the resource.

## `already-exists`

**Code** `already_exists` · **Status** 409 · **Title** Already exists

A resource with the same unique value already exists.

## `email-already-verified`

**Code** `email_already_verified` · **Status** 409 · **Title** Email address already verified

The email address is already verified.

## `verification-token-used`

**Code** `verification_token_used` · **Status** 409 · **Title** Verification token used

The email verification token has already been used.

## `verification-token-expired`

**Code** `verification_token_expired` · **Status** 410 · **Title** Verification token expired

The email verification token has expired.

## `request-timeout`

**Code** `request_timeout` · **Status** 408 · **Title** Request timeout

The request did not arrive whole within the time the server waits for it.

## `precondition-failed`

**Code** `precondition_failed` · **Status** 412 · **Title** Precondition failed

The `If-Match` value does not match the current `ETag` of the resource.

## `content-too-large`

**Code** `content_too_large` · **Status** 413 · **Title** Content too large

The request body is larger than the server accepts.

## `uri-too-long`

**Code** `uri_too_long` · **Status** 414 · **Title** URI too long

A segment of the request path is longer than the server accepts.

## `unsupported-media-type`

**Code** `unsupported_media_type` · **Status** 415 · **Title** Unsupported media type

The media type of the request body is not one the operation accepts.

## `misdirected-request`

**Code** `misdirected_request` · **Status** 421 · **Title** Misdirected request

The server does not answer for the host the request names, or not for this operation on that host.

## `unprocessable-content`

**Code** `unprocessable_content` · **Status** 422 · **Title** Unprocessable content

The request is well formed, but its content cannot be applied, such as a merge patch whose result fails the schema of the resource.

## `weak-password`

**Code** `weak_password` · **Status** 422 · **Title** Weak password

The new password is too weak. `errors` carries the feedback under `/password`.

## `precondition-required`

**Code** `precondition_required` · **Status** 428 · **Title** Precondition required

The update needs an `If-Match` header.

## `too-many-requests`

**Code** `too_many_requests` · **Status** 429 · **Title** Too many requests

The caller has sent too many requests. `Retry-After`, when present, says when to try again.

## `request-header-fields-too-large`

**Code** `request_header_fields_too_large` · **Status** 431 · **Title** Request header fields too large

The request headers are larger than the server accepts.

## `internal-error`

**Code** `internal_error` · **Status** 500 · **Title** Internal error

The server failed. `trace_id` finds the failure in the server log. Also sent with any other 5xx status that has no code of its own.

## `service-unavailable`

**Code** `service_unavailable` · **Status** 503 · **Title** Service unavailable

The server cannot answer now, for example while a dependency is down or it is too busy. `Retry-After`, when present, says when to try again.
