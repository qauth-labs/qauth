---
title: Realm policies
description: Every realm policy field with its default, the environment key that seeds it, which way is stricter and when a change is a security operation, generated from the schema in libs/server/realm-policy.
sidebar:
  order: 8
lastVerified: '2026-10-31'
---

<!-- Generated from libs/server/realm-policy by its tests. Do not edit by hand: change the schema and run `pnpm nx test server-realm-policy -- -u`. -->

A realm's policies are its own settings: token lifetimes, the sign-in and password rules, client
registration, mail and the environment posture
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 10).
They are defined once, as a typed schema with a version, in `libs/server/realm-policy`. The admin API's
realm representation, the realm file, the diff of two configurations and the rule that decides
which changes are security operations all come from it, and so does this page.

Today most of them are still read from the environment, for every realm. Some already live on the
realm row: the access, development access and refresh token lifetimes, the environment ceiling and
the scopes a dynamically registered client may hold. Nothing reads the `admin` group yet. Once the policies live on the realm row, the environment only seeds a
new realm's values, and the realm row owns them from then on.

Schema version: `1-rc.0`.

## How a change is classified

Each field says which way is stricter:

- **lower** or **higher**: a number, such as a lifetime or a threshold.
- `true` or `false`: a flag.
- **closer to** a value: an enum with an explicit order, from the loosest value to the strictest.
- **fewer entries**: a set of allowed values, such as scopes or trusted domains.
- **more entries**: a set of required values.
- **not ordered**: a change is neither a tightening nor a loosening.

A change is a tightening when it moves toward stricter, a loosening when it moves the other way,
and neutral when the field is not ordered. A change the schema cannot place counts as a loosening,
so an unknown direction fails closed: a value outside an enum's order, a set change that both adds
and removes an allowed value, and a direction the schema does not know.

The Class column says when a change needs `qauth:admin:security` instead of `qauth:admin:write`
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7):
never, only when it loosens, or on any change, in either direction. A security change carries the
[effects](/reference/security-operations/#effects) that make it one. A change of several fields
needs what its strictest change needs.

## Defaults and seeding

- The Default column is the value of a realm whose environment does not set the key in Seeded
  from. The environment only seeds: changing a key later changes no existing realm.
- A field added within a schema version always has a default, so a stored document that predates
  it still parses.
- **Secret** fields, such as the SMTP password, are write-only. Their value is never stored in the
  policy document and never returned: the realm representation shows only whether one is set, as
  `<name>Set`, and the realm file never holds one. A write sets one with its value and clears it
  with `null`; leaving it out keeps it, and a `<name>Set` sent back from the representation
  changes nothing. Setting or clearing a secret is always a security operation.
- **Environment-bound** fields describe the environment a realm runs in, such as its mail transport
  or a trust list. Promoting a sandbox configuration to a live realm leaves them out unless each is
  selected ([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
  Decision 11).

## Groups

### `tokens`

| Field                                          | Default  | Seeded from                 | Stricter when | Class                                                        | Description                                                                                                                      |
| ---------------------------------------------- | -------- | --------------------------- | ------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `tokens.accessTokenLifespanSeconds`            | `900`    | `ACCESS_TOKEN_LIFESPAN`     | lower         | `security` when loosened (`posture-loosening`), else `write` | How long an access token for a staging or production client is valid, in seconds.                                                |
| `tokens.developmentAccessTokenLifespanSeconds` | `28800`  | `DEV_ACCESS_TOKEN_LIFESPAN` | lower         | `security` when loosened (`posture-loosening`), else `write` | How long an access token for a development client is valid, in seconds; no staging or production client receives it.             |
| `tokens.refreshTokenLifespanSeconds`           | `604800` | `REFRESH_TOKEN_LIFESPAN`    | lower         | `security` when loosened (`posture-loosening`), else `write` | How long a refresh token is valid, in seconds.                                                                                   |
| `tokens.adminAccessTokenLifespanSeconds`       | `600`    | none                        | lower         | `security` when loosened (`posture-loosening`), else `write` | How long an access token for the admin API is valid, in seconds, at most 900 (ADR-019 Decision 7: admin tokens are short-lived). |

### `accounts`

| Field                             | Default | Seeded from                | Stricter when | Class                                                      | Description                                                                                                                                     |
| --------------------------------- | ------- | -------------------------- | ------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `accounts.requireVerifiedAccount` | `true`  | `REQUIRE_VERIFIED_ACCOUNT` | `true`        | `security` when loosened (`credential-path`), else `write` | Whether an account must be verified before a password sign-in succeeds; an unverified account is refused with the answer a wrong password gets. |

### `password`

| Field               | Default | Seeded from          | Stricter when | Class                                                      | Description                                                             |
| ------------------- | ------- | -------------------- | ------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------- |
| `password.minScore` | `2`     | `PASSWORD_MIN_SCORE` | higher        | `security` when loosened (`credential-path`), else `write` | The lowest zxcvbn strength score, from 0 to 4, a new password may have. |

### `bruteForce`

| Field                       | Default | Seeded from                     | Stricter when | Class                                                      | Description                                                                                                      |
| --------------------------- | ------- | ------------------------------- | ------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `bruteForce.enabled`        | `true`  | `FAILED_LOGIN_TRACKING_ENABLED` | `true`        | `security` when loosened (`credential-path`), else `write` | Whether repeated failed sign-ins for one identifier lock it out for a while; when off, failures are only logged. |
| `bruteForce.maxAttempts`    | `5`     | `FAILED_LOGIN_MAX_ATTEMPTS`     | lower         | `security` when loosened (`credential-path`), else `write` | How many failed sign-ins within the window lock an identifier out.                                               |
| `bruteForce.windowSeconds`  | `900`   | `FAILED_LOGIN_WINDOW`           | higher        | `security` when loosened (`credential-path`), else `write` | The window, in seconds, over which failed sign-ins are counted.                                                  |
| `bruteForce.lockoutSeconds` | `900`   | `FAILED_LOGIN_LOCKOUT_DURATION` | higher        | `security` when loosened (`credential-path`), else `write` | How long, in seconds, a locked-out identifier is refused before any password check.                              |

### `registration`

| Field                                           | Default                                        | Seeded from                           | Stricter when                                            | Class                                                    | Description                                                                                                                                                                      |
| ----------------------------------------------- | ---------------------------------------------- | ------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `registration.dynamicRegistrationAllowedScopes` | `openid`, `profile`, `email`, `offline_access` | `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` | fewer entries                                            | `security` when loosened (`token-content`), else `write` | The scopes a dynamically registered client may hold; a scope outside the list is dropped from the registration, and no scope of the reserved qauth: namespace can be listed.     |
| `registration.cimd.enabled`                     | `true`                                         | `CIMD_ENABLED`                        | `false`                                                  | `security` when loosened (`token-content`), else `write` | Whether an HTTPS URL is accepted as a client_id, its metadata fetched from that URL (Client ID Metadata Documents).                                                              |
| `registration.cimd.trustPolicy`                 | `accept-any-https`                             | `CIMD_TRUST_POLICY`                   | closer to `allowlist` (`accept-any-https` < `allowlist`) | `security` when loosened (`token-content`), else `write` | Which hosts a metadata-document client_id may have: any HTTPS host, or only the trusted domains.                                                                                 |
| `registration.cimd.trustedDomains`              | empty                                          | `CIMD_TRUSTED_DOMAINS`                | fewer entries                                            | `security` when loosened (`token-content`), else `write` | The hosts the allowlist policy accepts, stored in lower case; an entry `*.example.com` accepts every subdomain of `example.com` but not `example.com` itself. Environment-bound. |

### `mail`

| Field                                   | Default | Seeded from                                        | Stricter when | Class                                                        | Description                                                                                                                                        |
| --------------------------------------- | ------- | -------------------------------------------------- | ------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mail.provider`                         | `mock`  | `EMAIL_PROVIDER`                                   | not ordered   | `security` on any change (`credential-path`)                 | Which transport sends the realm mail: mock (logs only), resend or smtp. Environment-bound.                                                         |
| `mail.fromAddress`                      | none    | `EMAIL_FROM_ADDRESS`                               | not ordered   | `security` on any change (`credential-path`)                 | The address the realm mail is sent from. Environment-bound.                                                                                        |
| `mail.fromName`                         | `QAuth` | `EMAIL_FROM_NAME`                                  | not ordered   | `security` on any change (`credential-path`)                 | The sender name the realm mail shows. Environment-bound.                                                                                           |
| `mail.smtp.host`                        | none    | `SMTP_HOST`                                        | not ordered   | `security` on any change (`credential-path`)                 | The SMTP server the smtp transport connects to. Environment-bound.                                                                                 |
| `mail.smtp.port`                        | none    | `SMTP_PORT`                                        | not ordered   | `security` on any change (`credential-path`)                 | The port of the SMTP server. Environment-bound.                                                                                                    |
| `mail.smtp.secure`                      | `true`  | `SMTP_SECURE`                                      | not ordered   | `security` on any change (`credential-path`)                 | Whether the SMTP connection uses TLS from its start. Environment-bound.                                                                            |
| `mail.smtp.user`                        | none    | `SMTP_USER`                                        | not ordered   | `security` on any change (`credential-path`)                 | The user name the smtp transport signs in with. Environment-bound.                                                                                 |
| `mail.smtp.password`                    | none    | `SMTP_PASSWORD`                                    | not ordered   | `security` on any change (`credential-path`)                 | The password the smtp transport signs in with. Secret: write-only, never stored in the policy document, shown as `passwordSet`. Environment-bound. |
| `mail.resend.apiKey`                    | none    | `RESEND_API_KEY`                                   | not ordered   | `security` on any change (`credential-path`)                 | The API key the resend transport sends with. Secret: write-only, never stored in the policy document, shown as `apiKeySet`. Environment-bound.     |
| `mail.verificationTokenExpirySeconds`   | `86400` | `EMAIL_VERIFICATION_TOKEN_EXPIRY`                  | lower         | `security` when loosened (`posture-loosening`), else `write` | How long a verification link is valid, in seconds, at least one hour. Environment-bound.                                                           |
| `mail.invalidateExistingTokensOnResend` | `true`  | `EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND` | `true`        | `write`                                                      | Whether sending a new verification link makes the earlier ones invalid, so only the latest works. Environment-bound.                               |

### `posture`

| Field                          | Default      | Seeded from | Stricter when                                                     | Class                                                        | Description                                                                                                                                                              |
| ------------------------------ | ------------ | ----------- | ----------------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `posture.maxEnvironmentLaxity` | `production` | none        | closer to `production` (`development` < `staging` < `production`) | `security` when loosened (`posture-loosening`), else `write` | The laxest environment profile a client of the realm may get; a client set to a laxer one gets this one. Environment-bound. [More](/operate/environment-authorization/). |

### `admin`

| Field                               | Default | Seeded from | Stricter when | Class                                       | Description                                                                                                        |
| ----------------------------------- | ------- | ----------- | ------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `admin.twoAdminMandatoryOperations` | empty   | none        | more entries  | `security` on any change (`administration`) | The admin operations that need a second admin approval in this realm, by operation id.                             |
| `admin.workloadIssuers`             | empty   | none        | fewer entries | `security` on any change (`administration`) | The HTTPS issuers whose workload tokens a CI service account may exchange for admin API tokens. Environment-bound. |

## Versions

The schema version is a string. Until QAuth 1.0.0 it is `1-rc.<M>`, and nothing about it is
promised: a breaking change raises `<M>`
([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)). From the release that ships
1.0.0 it is `1`, and inside version 1 every change is additive: a new field comes with a default,
and no field is removed. Other areas add their groups to the same schema, such as browser sessions
and sign-in methods; a group's name is taken once.

The effects named above are the closed list of 11 effect tags on
[Security operations](/reference/security-operations/).
