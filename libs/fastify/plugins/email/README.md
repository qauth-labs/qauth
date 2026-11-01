# Fastify Email Plugin

Fastify plugin for the mail QAuth sends. It decorates the instance with `emailService`, the mail
service of every realm, and `emailVerificationTokenUtils`.

## Overview

Each realm sends its mail through its own transport and from its own sender
([ADR-019](../../../../docs/adr/019-deployment-topology-and-trust-boundaries.md) Decision 10,
issue #529):

- the transport (`mock`, `smtp` or `resend`), the sender address and name, and the SMTP host, port,
  TLS setting and user are the realm's `mail.*` policies, on the realm row;
- the SMTP password and the Resend API key sit in the realm's secret store, encrypted with the
  realm's data-at-rest key, and only the mail sender reads them.

The plugin holds no transport of its own. Every mail names its realm; the plugin reads the realm's
mail policies through the `source` it is given, builds the realm's provider from them, and keeps it
for the policy counter it read (`policies_version`). A change of the transport, the sender or the
password raises the counter, so it reaches the next mail without a restart.

## Usage

```typescript
import { emailPlugin } from '@qauth-labs/fastify-plugin-email';

await fastify.register(emailPlugin, {
  // Where each realm's mail policies and secrets are read, on every mail.
  source: {
    async read(realmId) {
      const snapshot = await fastify.policyStore.get(realmId);
      if (snapshot === undefined) return undefined;
      return {
        version: snapshot.version,
        mail: snapshot.policies.mail,
        // `secrets` is the realm secret store the caller built
        // (`createRealmSecretStoreOfRealms`) and hands only to the mail sender.
        secretOf: (path) => secrets.getForUse(realmId, path),
      };
    },
  },
  // What every realm's mail shares: the lifetime the verification mail states.
  serviceConfig: { verificationTokenExpiry: 86400 },
});

// In a route: the realm the account belongs to, and the link base, its issuer.
await fastify.emailService.sendVerificationEmail(realm.id, address, token, {
  baseUrl: realm.issuer,
});
await fastify.emailService.sendAccountExistsEmail(realm.id, address);
```

The auth server builds its source in `apps/auth-server/src/app/helpers/realm-secrets.ts`
(`realmMailSource`).

## API

### `emailService`

Type: `RealmEmailService` (from `@qauth-labs/server-email`).

- `sendVerificationEmail(realmId, to, token, link, options?)`: a verification mail whose link is
  `${link.baseUrl}/auth/verify?token=…`.
- `sendAccountExistsEmail(realmId, to, options?)`: the notice that someone tried to register an
  address again. No link, no token.

Both resolve with an `EmailResult` (`success`, `messageId` or `error`) and reject with
`RealmMailUnavailableError` when the realm cannot send mail: there is no such realm, or its
transport lacks a setting or its secret. The error names the realm id and the policy path, never a
value.

### `emailVerificationTokenUtils`

`generateVerificationToken`, `hashToken`, `isValidTokenFormat` and `constantTimeCompare`, from
`@qauth-labs/server-email`.

## Transports

- `mock` delivers nothing: it records each mail in memory, and logs it to the console outside
  tests. It needs no setting.
- `smtp` sends through nodemailer to `mail.smtp.host` and `mail.smtp.port`, over TLS from the start
  when `mail.smtp.secure` is on, signing in as `mail.smtp.user` with the stored password.
- `resend` sends through the Resend API with the stored API key.

`smtp` and `resend` send from `mail.fromName <mail.fromAddress>`. The realm policy update refuses a
transport without what it sends with, so a stored transport normally has it; one that does not
makes its mail fail, naming the missing path.

## Development

```bash
pnpm nx typecheck fastify-plugin-email
pnpm nx lint fastify-plugin-email
```

The per-realm sender and its tests live in `@qauth-labs/server-email` (`src/lib/realm-mail.ts`).

## Related Libraries

- [`@qauth-labs/server-email`](../../../server/email/README.md): the providers, the templates and
  the per-realm mail service
- [`@qauth-labs/fastify-plugin-realm-policy`](../realm-policy): the realm policy store and the realm
  secret store

## License

Apache-2.0
