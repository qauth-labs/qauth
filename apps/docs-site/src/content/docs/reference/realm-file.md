---
title: Realm file
description: The declarative realm file, format urn:qauth:realm-file:v1-rc.0. Its top-level keys and sections, the natural keys an import matches by, what a file never holds, and the rules by which the format grows within version 1.
sidebar:
  order: 9
lastVerified: '2026-11-16'
---

A realm file describes one realm's configuration as a JSON document: its
[policies](/reference/realm-policies/), the clients the operator manages, the
scopes granted to Client ID Metadata Document (CIMD) clients, the protected
resources it registers and the developer portal's system client. It holds no
secret value. The admin API and the CLI will export and import it, and an import
first shows a dry-run diff of every change, authorized change by change
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
Decision 11). That dry run is served now, for the `policies` and `clients`
sections ([The import plan](#the-import-plan)); applying an import comes later. The format itself is fixed now, and it is inside the 1.0
stability promise
([ADR-018](/reference/records/adr/018-1-0-scope-and-stability/), §5).

The seed manifest of `db:seed-oauth-clients` is a realm file as it is: its
`realm`, `clients`, `cimd_clients`, `resources` and `system_client` are the
file's, with the same schemas. A realm file can say more than a manifest: its
`format`, its `policies` and each client's `environment`. It also refuses
three mistakes the seed lets pass: a `client_id` listed twice, a member of a
key set beside `keys`, and a URL with a user name or password.

The JSON Schema (draft 2020-12) of the format is published at
[`/schemas/realm-file-v1-rc.0.json`](/schemas/realm-file-v1-rc.0.json). It is
generated from the parser's own schema.

## The file

| Key             | Required | Holds                                                                                                                                                                   |
| --------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `format`        | no       | `urn:qauth:realm-file:v1-rc.0`, which a file without the key is read as. A file of another format is refused, and the message names both.                               |
| `realm`         | yes      | The realm's name. It only advises: the caller of an import chooses the target realm, and another name there is a warning, so a sandbox's file can go to its live realm. |
| `policies`      | no       | The realm's policies.                                                                                                                                                   |
| `clients`       | no       | The operator-managed OAuth clients.                                                                                                                                     |
| `cimd_clients`  | no       | The operator's grants to CIMD clients.                                                                                                                                  |
| `resources`     | no       | The realm's protected resources.                                                                                                                                        |
| `system_client` | no       | The developer portal's system client.                                                                                                                                   |

A section a file leaves out says nothing about what it describes. Within a
section, every member a file leaves out takes its default.

Every object is strict, but a JWK. A member the format does not name is
refused, with its path and, where the format has one, the reason it is not in a
file: a typo fails, a secret fails, and a section of a later release fails
instead of being skipped. So is `$schema`: point your editor at the published
schema by its own settings, such as VS Code's `json.schemas`, not from inside
the file. A JWK keeps members the format does not name, since
[RFC 7517](https://www.rfc-editor.org/rfc/rfc7517#section-4) leaves a key's
members open, and refuses its private ones.

## A full example

```json
{
  "format": "urn:qauth:realm-file:v1-rc.0",
  "realm": "notes",
  "policies": {
    "tokens": { "accessTokenLifespanSeconds": 600 },
    "accounts": { "allowSignUp": true },
    "password": { "minLength": 15, "breachListSource": "k_anonymity" },
    "registration": {
      "dynamicRegistrationAllowedScopes": ["openid", "profile"],
      "cimd": { "trustPolicy": "allowlist", "trustedDomains": ["apps.example.com"] }
    },
    "mail": {
      "provider": "smtp",
      "fromAddress": "no-reply@notes.example.com",
      "fromName": "Notes",
      "smtp": { "host": "smtp.example.com", "port": 587, "secure": true, "user": "mailer" }
    },
    "posture": { "maxEnvironmentLaxity": "production" }
  },
  "clients": [
    {
      "client_id": "notes-api",
      "name": "Notes API",
      "description": "The notes service: it manages its SSF stream as itself.",
      "grant_types": ["client_credentials"],
      "scopes": ["notes:sync", "ssf:stream"],
      "client_credentials_scopes": ["ssf:stream"],
      "audience": ["https://notes.example.com/api"],
      "token_endpoint_auth_method": "private_key_jwt",
      "jwks_uri": "https://notes.example.com/.well-known/jwks.json"
    },
    {
      "client_id": "notes-web",
      "name": "Notes",
      "grant_types": ["authorization_code", "refresh_token"],
      "response_types": ["code"],
      "scopes": ["email", "notes:read", "offline_access", "openid", "profile"],
      "redirect_uris": ["https://notes.example.com/callback"],
      "require_pkce": true,
      "token_endpoint_auth_method": "none",
      "environment": "production"
    },
    {
      "client_id": "research-agent",
      "name": "Research agent",
      "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"],
      "scopes": ["agent:readonly", "notes:read"],
      "token_endpoint_auth_method": "private_key_jwt",
      "jwks": {
        "keys": [
          {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "kid": "research-agent-2026-11"
          }
        ]
      },
      "is_agent": true,
      "max_agent_mode": "readonly"
    }
  ],
  "cimd_clients": [
    {
      "client_id": "https://client.example.com/oauth/metadata.json",
      "scopes": ["notes:read", "offline_access"],
      "audience": ["https://notes.example.com/api"]
    }
  ],
  "resources": [
    {
      "resource": "https://mcp.notes.example.com/mcp",
      "scopes": [
        { "scope": "files:read", "text": { "en": "Read your notes' files" } },
        { "scope": "files:write", "text": { "en": "Change your notes' files" }, "sensitive": true }
      ],
      "clients": "any_client"
    }
  ],
  "system_client": {
    "redirect_uris": ["https://portal.notes.example.com/auth/callback"],
    "jwks_uri": "https://portal.notes.example.com/.well-known/jwks.json"
  }
}
```

This file selects the `smtp` mail transport and holds no SMTP password. The
password is set on the target realm itself, and an import lists every secret
the realm still needs as `secretsToSet`.

## Sections

Each section has a natural key: the member an import matches the realm's state
by. A natural key names one item across every section that has it, so a
`client_id` appears once in a file, whether in `clients`, `cimd_clients` or
`system_client`. No id the server generates ever appears.

### `policies`

Natural key: none. Each field is matched by its path, such as
`tokens.accessTokenLifespanSeconds`.

The policies have the shape of the `policies` object of the admin API's realm
representation: groups of `camelCase` fields, as
[Realm policies](/reference/realm-policies/) lists them with their defaults. One
difference: the representation shows a secret field `<name>` as `<name>Set`,
and a realm file has neither. A file with `mail.smtp.password`,
`mail.resend.apiKey` or their `Set` flags is refused. A field the file leaves
out takes its default, and so does a field a later version of the policy
schema adds.

### `clients`

Natural key: `client_id`.

Each entry is a seed-manifest client, with its OAuth metadata names
([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)): `client_id`, `name`,
`description`, `grant_types`, `response_types`, `scopes`, `audience`,
`redirect_uris`, `require_pkce`, `token_endpoint_auth_method`, `is_agent`,
`max_agent_mode`, `jwks`, `jwks_uri`, and the other operator-set fields the
[seed manifest](/operate/docker/#first-party-clients-adr-017) takes, such as
`client_credentials_scopes`, `id_jag_targets` and the first-party profile. The
manifest's rules between fields hold here too: `jwks` or `jwks_uri` but not both,
a key set for `private_key_jwt`, and the rest. A key set, `jwks`, holds `keys`
and nothing else.

One field is the realm file's own:

- `environment`: `development`, `staging` or `production`, the client's
  environment profile
  ([ADR-008](/reference/records/adr/008-environment-aware-authorization/)).
  Left out, the client is `production`, the fail-safe default, and the realm's
  `posture.maxEnvironmentLaxity` caps it. A sandbox realm's client says
  `staging`.

Only clients the operator manages are in a file. A client a developer owns or
that registered itself (dynamic registration) is not: `developer_id` and
`dynamic_registered_at` are refused. No `client_secret` either: a client's secret
is set on the target realm, never copied.

### `cimd_clients`

Natural key: `client_id`, the URL of the client's metadata document.

Each entry is the operator's grant to a CIMD client: `scopes`,
`client_credentials_scopes` and `audience`
([Granting scopes to a CIMD client](/operate/docker/#granting-scopes-to-a-cimd-client)).
The client's document owns every other field, so the file holds none of them.

### `resources`

Natural key: `resource`, the resource indicator
([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)).

Each entry registers a protected resource: its `resource`, the `scopes` it
defines with their consent texts by locale, and `clients`, `"any_client"` or a
list of `client_id`s
([Registering a protected resource's scopes](/operate/docker/#registering-a-protected-resources-scopes)).

### `system_client`

Natural key: `client_id`, `system` unless the file or `SYSTEM_CLIENT_ID` names
another.

The developer portal's system client, as the migration runner provisions it:
`redirect_uris`, `jwks` or `jwks_uri`, and optionally `client_id` and
`first_party_reason`.

## What a file never holds

- The realm's host, its endpoint hosts and its issuer.
- The realm's keys and its passkey RP ID.
- Users and sessions.
- Secret values: a client's `client_secret`, a secret policy field such as the
  SMTP password, a JWK's private members (`d`, `p`, `q`, `dp`, `dq`, `qi`,
  `oth`, `k`, `priv`), and a user name or password in a URL, such as
  `https://user:password@keys.example.com/jwks.json`. No string of a file is
  such a URL, whatever member holds it. An import lists the secrets the target
  realm still needs as `secretsToSet`.
- Ids the server generates, and timestamps.
- The pairing of a sandbox realm with its live realm.
- Clients a developer owns and dynamically registered clients.

## Validation

The parser refuses a file with every issue it has, each with the path of the
member at fault, such as `/clients/0/client_secret`. No message quotes a value
that holds a secret. The published JSON Schema checks the shape: every member,
type, enum, length and range, that no other member appears, that no JWK holds
private material, and that no string is a URL with a user name or password in
its usual form, `scheme://user:password@host`. Some rules only the parser
checks, before any import:

- the rules between values: a `client_id` or a `resource` listed once in a
  file, and the seed manifest's rules between a client's fields, such as
  `jwks` or `jwks_uri` but not both;
- the rules on one value that no JSON Schema keyword states, such as a
  redirect URI the consent screen can show where the code goes to, the shape
  of a CIMD `client_id` and of a resource indicator, the members a JWK of each
  key type needs, the reserved `qauth:` scopes and `urn:qauth:aud:` audiences,
  a back-channel logout URI, a passkey origin and a verified domain;
- a URL with a user name or password in a form other than the usual one, as a
  URL parser reads `https:/user:password@host`.

The JSON Schema, in turn, reads a URL by RFC 3986, as JSON Schema's `uri`
format does, where the parser reads it as a URL parser does: an editor may flag
a URL with a host in Unicode or with a space, which the parser accepts.

## The import plan

`POST /admin/v1-rc.0/realms/{realmId}/imports` with `mode: "dry-run"` and the
file as `file` answers the plan of importing it into that realm
(`realms.imports.plan`, a read: `qauth:admin:read` is enough). It applies
nothing.

- **Each change** names its `section`, its item by the natural key (`key`, a
  client's `client_id`; `null` for `policies`), the field's `path`, its `op`
  (`create`, `update` or `delete`), the value `before` and `after`, its
  `direction` (`tightening`, `loosening` or `neutral`; an unknown direction
  counts as loosening), and the `class`, `effects`, `permissions` and
  `scopes` of the single operation it equals: a policy field as
  `realms.policies.update` judges it, a client field as `clients.update`
  does, and creating or deleting a client is a security change with the
  effect `token-content`, as `clients.create` and `clients.delete` are.
  `environmentBound` marks a value that describes where the realm runs;
  `needsSecret` marks a change that leaves the realm needing a secret it
  does not hold.
- **A client field** tightens or loosens as its table says: fewer
  `redirect_uris`, `scopes`, `grant_types`, `response_types` or `audience`
  entries is stricter; `require_pkce: true` is stricter;
  `private_key_jwt` is stricter than the two secret methods, which are
  stricter than `none`; `is_agent: false` and a lower `max_agent_mode` are
  stricter; any change of `jwks` or `jwks_uri` loosens; an `environment`
  toward `production` is stricter, and toward `development` loosens with the
  effect `posture-loosening`; `name` and `description` are neutral.
- **The plan** is as strict as its strictest change: `security`, with an
  approval, once one change is. It lists every effect, permission and scope
  its changes need, the secrets the file's choices need and the realm lacks
  (`secretsToSet`), and a `digest`: the SHA-256, base64url, of the RFC 8785
  form of the realm id, the base `policies_version`, the prune flag and the
  changes. Anything the plan would do, and the base version, changes it.
- **Nothing is deleted** unless the request sets `prune: true`: a client the
  file leaves out stays, and a section the file leaves out says nothing.
- **Refused** (422, each issue a pointer into the request's `file`): a file
  the parser refuses; a file that holds `cimd_clients`, `resources` or
  `system_client`, which the import does not plan yet; and a file whose
  `clients` names a client no realm file manages: a developer's, one that
  registered itself, a CIMD client, the system client or a service
  account's.

No plan holds a secret: a secret policy field shows only `set` or `not set`,
and a URL the realm stores with a user name or password shows them as `***`.

## How the format grows

The format grows within version 1 by these rules:

- A later minor release may add an optional section: scopes, roles, groups,
  mappers, identity providers, resource servers, agent types or brand. The
  area that builds the feature adds its section.
- A section is added with its schema, its natural key and its diff rules. No
  section is added without them.
- A server that reads a file with a section it does not know refuses the file
  and names the section. It never skips it.
- A field is added to a section only as an optional field with a default.
- Before QAuth 1.0.0, a breaking change raises the release-candidate number:
  `urn:qauth:realm-file:v1-rc.1`. From 1.0.0 the format is
  `urn:qauth:realm-file:v1`, and a breaking change needs
  `urn:qauth:realm-file:v2`.
- Arrays that are sets are written in a canonical order, so files compare
  cleanly.

A file QAuth writes is in canonical order: `format` and `realm` first, then
the sections in the order above. Each list of entries is sorted by its natural
key, and each set is sorted with each value once: a client's grant types,
scopes, audience and redirect URIs, a resource's scopes, and each policy field
that [Realm policies](/reference/realm-policies/) marks "fewer entries" or "more
entries". A scope's texts are sorted by locale. Strings sort by UTF-16 code
unit, as [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) sorts object
members. A key set keeps its keys in the order written, and each key's
members are sorted. A file a person writes may be in any
order.
