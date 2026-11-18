---
title: CI token exchange
description: Let a CI job call the admin API with no stored credential, by trusting its CI platform's workload tokens in the operator realm's policies and exchanging one for a short-lived, DPoP-bound admin token of a service account.
sidebar:
  order: 16
lastVerified: '2026-11-18'
---

A CI job can call the admin API as a [service account](/operate/service-accounts/)
without holding any credential of its own. Its CI platform signs a short-lived
OpenID Connect token that names the job: the **workload token**. The job
exchanges that token at the token endpoint (RFC 8693 token exchange) for an
admin token of the service account, bound to a DPoP key the job makes for the
run (RFC 9449). Nothing is stored in the CI system: no private key, no secret,
no static admin key.

What the job may do is decided in the operator realm
([Topology](/operate/topology/#the-operator-realm)), by its admins:

- the realm policy `admin.workloadIssuers` lists the CI platforms it trusts,
  and for each one the audience, the subject and the service account;
- the service account's admin grants decide which admin scopes its token
  carries, as for any service account.

## How a token is exchanged

1. The job asks its CI platform for a workload token with the audience the
   policy names.
2. It sends the token to the operator realm's token endpoint, with a DPoP
   proof.
3. QAuth checks the token against the policy:
   - its `iss` must be a listed issuer, byte for byte. QAuth fetches that
     issuer's discovery document and JWK Set, and nothing for an issuer the
     policy does not list;
   - its signature must verify, with an algorithm of the asymmetric set
     (`EdDSA`, `RS256`, `ES256`), and its `exp` and `nbf` must hold;
   - it must be at most 10 minutes old, counted from its `iat`;
   - its `aud` must hold the entry's audience;
   - its `sub` must match the entry's subject;
   - its `jti` must be new: a workload token is exchanged once.
4. The service account the entry names gets an admin token: `sub` its
   account, `client_id` its client's, the admin API's audience alone, bound
   to the proof's key, for the realm's admin token lifetime (at most 900
   seconds). No refresh token.

Only `iss`, `sub`, `aud`, `iat`, `exp`, `nbf` and `jti` are read. Claims such
as `repository`, `ref` or `environment` count for nothing: put what must match
into the subject.

## Before you start

- The admin API is on (`ADMIN_API_ENABLED`), and so is DPoP
  (`DPOP_ENABLED`): without DPoP the exchange is refused.
- The service account exists, in the operator realm, with the admin grants
  the job needs ([Create one](/operate/service-accounts/#create-one)). Its
  client's key is not used by the exchange: you may keep the private key
  offline, or not keep it at all.
- The issuer's discovery document
  (`<issuer>/.well-known/openid-configuration`) and its `jwks_uri` are
  reachable from the auth server over HTTPS. An issuer on a private address
  needs an entry naming the operator realm in the file
  `EGRESS_ALLOWLIST_PATH` names ([Configuration](/operate/configuration/));
  the `jwks_uri` must be on a public address all the same.

## Add a workload issuer

Each entry of `admin.workloadIssuers` has four members:

| Member           | What it is                                                                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `issuer`         | The token's `iss`, an `https` URL, compared byte for byte: no trailing slash, case or path is forgiven.                                    |
| `audience`       | A value the token's `aud` must hold. The job asks its CI platform for a token with this audience; pick one no other service of yours uses. |
| `subject`        | The token's `sub`: exactly, or by a prefix when it ends in `:` or `/` and then `*`. No other character is a wildcard.                      |
| `serviceAccount` | The name of the service account the token acts as.                                                                                         |

A prefix ends at a separator of the subject, a `:` or a `/`:
`repo:acme/infra:*` matches every job of the repository `acme/infra`, and
`repo:acme/infra*`, which would also match `acme/infra-tools`, is refused. When
a token matches more than one entry, the most specific wins: an exact subject
over any prefix, a longer prefix over a shorter. Two entries as specific that
name different service accounts refuse the token.

Choose the subject with care: on an issuer that many tenants share, it is all
that tells your jobs from theirs, since a job asks for any audience it likes.

- Pin it to what only trusted people can start: a protected branch or a
  protected environment. A prefix over a whole repository also covers its
  pull request runs and every branch anyone with write access pushes.
- A subject that names an organization, a project or a repository by name
  matches whoever holds that name next, after a rename or a deletion. Where
  the CI platform can put the owner's and the repository's numeric ids into
  the subject, have it do so, and list the subject with them.

An entry names its service account by name. Deleting the service account
leaves the entry in the list: remove it too, or a later service account
given the same name takes its trust.

The list is a realm policy, and changing it in any way is a security
operation (effect `administration`): it needs `qauth:admin:security`, and an
approval when the realm makes it one
([Security operations](/reference/security-operations/)). A JSON Merge Patch
replaces a list whole, so send every entry the realm should keep:

```http
PATCH /admin/v1-rc.0/realms/<operator realm id>/policies HTTP/1.1
Host: <the admin listener>
Authorization: DPoP <admin token>
DPoP: <proof>
Content-Type: application/merge-patch+json
If-Match: "<the realm's ETag>"

{
  "admin": {
    "workloadIssuers": [
      {
        "issuer": "https://token.actions.githubusercontent.com",
        "audience": "https://auth.example.com/ci",
        "subject": "repo:acme/infra:ref:refs/heads/main",
        "serviceAccount": "ci-realm-import"
      },
      {
        "issuer": "https://gitlab.example.com",
        "audience": "https://auth.example.com/ci",
        "subject": "project_path:platform/realms:ref_type:branch:ref:main",
        "serviceAccount": "ci-realm-import"
      }
    ]
  }
}
```

The list holds at most 20 entries, each issuer, audience and subject once.
The policy is environment-bound: promoting a sandbox configuration leaves it
out unless it is selected. [Realm policies](/reference/realm-policies/#admin)
lists it with the others.

## Call the exchange from a CI job

The job makes a DPoP key for the run, asks its CI platform for a workload
token, and sends it to the operator realm's token endpoint:

```http
POST /oauth/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: <proof for POST https://auth.example.com/oauth/token>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<workload token>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&resource=urn:qauth:aud:admin:v1-rc.0
&scope=qauth:admin:read qauth:admin:write
```

- No client authentication: no `client_secret`, no `client_assertion`, no
  `Authorization` header. A `client_id`, if the job's library sends one, must
  be the service account's client.
- `resource` is the admin API's audience, and nothing else.
- `scope` names the admin scopes the job needs. The token carries those the
  service account's grants allow; a request left with none is refused.
- The answer is an access token (`issued_token_type`
  `urn:ietf:params:oauth:token-type:access_token`, `token_type` `DPoP`) and
  its `expires_in`. Call the admin API with it under the `DPoP` scheme and a
  fresh proof for each call. When it expires, ask the CI platform for a new
  workload token and exchange it: a workload token is exchanged once.

How the job gets its workload token depends on its CI platform. Two
examples:

- **Example, GitHub Actions:** give the job `permissions: id-token: write`,
  then ask for a token with the entry's audience. The issuer is
  `https://token.actions.githubusercontent.com`, and the subject names the
  repository and the branch or environment, such as
  `repo:acme/infra:ref:refs/heads/main` or `repo:acme/infra:environment:production`.

  ```bash
  WORKLOAD_TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://auth.example.com/ci" | jq -r .value)
  ```

- **Example, GitLab CI/CD:** declare an ID token with the entry's audience;
  the job finds it in the variable it names. The issuer is the instance's
  URL, and the subject names the project and the ref, such as
  `project_path:platform/realms:ref_type:branch:ref:main`.

  ```yaml
  import-realm:
    id_tokens:
      WORKLOAD_TOKEN:
        aud: https://auth.example.com/ci
  ```

Run the exchange in the step that needs the admin API, not at the start of a
long job: the token endpoint refuses a workload token issued more than 10
minutes earlier.

## Security operations need a human

A service account never approves. A security operation filed with an
exchanged token waits for a human admin's approval, as one filed with the
service account's own token does
([Security operations need a human](/operate/service-accounts/#security-operations-need-a-human)).

## When the exchange is refused

Every refusal of the workload token, and of the service account it maps to,
answers the same `400 invalid_request`, so a caller learns neither which
issuers and subjects are trusted nor which service accounts exist. The
`token.request_failed` event, and a line in the log, name the reason:

- `workload_issuer_not_listed`, `workload_audience_invalid`,
  `workload_subject_not_listed`, `workload_ambiguous_service_account`: the
  token matches no entry;
- `workload_too_old`, `workload_issued_in_future`,
  `workload_signature_invalid` (a bad signature, or `exp` or `nbf`),
  `workload_claims_invalid` (no `iat`, `exp`, `sub` or `jti`): the token is
  not usable;
- `workload_unresolvable_key`: no key of the issuer's JWK Set verifies it, or
  its documents could not be fetched;
- `workload_replayed`: its `jti` was exchanged before;
  `workload_replay_store_unavailable`: Redis could not record it, and the
  exchange fails closed;
- `workload_service_account_disabled`, `workload_service_account_unknown`,
  `workload_service_account_account_inactive`,
  `workload_service_account_client_unusable`: the service account may not
  act now.

The request's own mistakes say what to fix: `invalid_dpop_proof` without a
proof, `invalid_target` for a `resource` other than the admin API's audience,
and `invalid_request` with a description for client credentials, an
`actor_token` or another `requested_token_type`. A successful exchange is a
`token.issued` event naming the service account's account and client, and an
`info` line in the log naming the issuer and subject that matched.

## See also

- [Service accounts](/operate/service-accounts/) — create one, its grants,
  and how to disable it.
- [Realm policies](/reference/realm-policies/#admin) — `admin.workloadIssuers`.
- [Upgrades](/operate/upgrades/#workload-issuers-name-their-audience-subject-and-service-account)
  — the realm policy schema `1-rc.3`.
