# Configuration Library

Composable Zod schemas for environment variable validation. This library provides type-safe, reusable configuration schemas that apps can compose based on their needs.

## Overview

The `@qauth-labs/server-config` library provides:

- **Composable schemas** - Mix and match only the configuration you need
- **Type-safe validation** - Full TypeScript support with Zod validation
- **Environment variable parsing** - Automatic `.env` file loading and validation
- **Reusable patterns** - Common configuration patterns for database, cache, auth, etc.

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import { baseEnvSchema, databaseEnvSchema, parseEnv } from '@qauth-labs/server-config';
```

## Usage

### Basic Usage

```typescript
import { z } from 'zod';
import { baseEnvSchema, databaseEnvSchema, parseEnv } from '@qauth-labs/server-config';

// Compose only the schemas you need using spread syntax
const envSchema = z.object({
  ...baseEnvSchema.shape,
  ...databaseEnvSchema.shape,
});

// Parse and validate environment variables
const env = parseEnv(envSchema);

// env is fully typed
console.log(env.PORT); // number
console.log(env.DATABASE_URL); // string
```

### Full Composition Example

```typescript
import { z } from 'zod';
import {
  authEnvSchema,
  baseEnvSchema,
  databaseEnvSchema,
  parseEnv,
  passwordEnvSchema,
  rateLimitEnvSchema,
  redisEnvSchema,
} from '@qauth-labs/server-config';

// Compose all schemas with app-specific extensions using spread syntax
const envSchema = z.object({
  ...baseEnvSchema.shape,
  ...databaseEnvSchema.shape,
  ...redisEnvSchema.shape,
  ...passwordEnvSchema.shape,
  ...authEnvSchema.shape,
  ...rateLimitEnvSchema.shape,
  // App-specific env vars
  CORS_ORIGIN: z.string().optional(),
});

export const env = parseEnv(envSchema);
```

## Available Schemas

### baseEnvSchema

Common server configuration.

| Variable    | Type   | Default       | Description         |
| ----------- | ------ | ------------- | ------------------- |
| `NODE_ENV`  | enum   | `development` | Node environment    |
| `HOST`      | string | `0.0.0.0`     | Server host address |
| `PORT`      | number | `3000`        | Server port         |
| `LOG_LEVEL` | enum   | `info`        | Logging level       |

### databaseEnvSchema

PostgreSQL database configuration.

| Variable                     | Type   | Default | Description               |
| ---------------------------- | ------ | ------- | ------------------------- |
| `DATABASE_URL`               | url    | -       | PostgreSQL connection URL |
| `DB_POOL_MAX`                | number | `20`    | Max connections in pool   |
| `DB_POOL_MIN`                | number | `2`     | Min connections in pool   |
| `DB_POOL_IDLE_TIMEOUT`       | number | `10000` | Idle timeout (ms)         |
| `DB_POOL_CONNECTION_TIMEOUT` | number | `2000`  | Connection timeout (ms)   |

### redisEnvSchema

Redis cache configuration.

| Variable                   | Type   | Default | Description             |
| -------------------------- | ------ | ------- | ----------------------- |
| `REDIS_URL`                | url    | -       | Redis connection URL    |
| `REDIS_HOST`               | string | -       | Redis host (if no URL)  |
| `REDIS_PORT`               | number | -       | Redis port (if no URL)  |
| `REDIS_PASSWORD`           | string | -       | Redis password          |
| `REDIS_DB`                 | number | -       | Redis database number   |
| `REDIS_MAX_RETRIES`        | number | `3`     | Max retries per request |
| `REDIS_CONNECTION_TIMEOUT` | number | `10000` | Connection timeout (ms) |
| `REDIS_COMMAND_TIMEOUT`    | number | `5000`  | Command timeout (ms)    |

### passwordEnvSchema

Password hashing and validation configuration.

| Variable               | Type   | Default | Description              |
| ---------------------- | ------ | ------- | ------------------------ |
| `PASSWORD_MIN_SCORE`   | number | `2`     | Min strength score (0-4) |
| `PASSWORD_MEMORY_COST` | number | `65536` | Argon2 memory cost (KB)  |
| `PASSWORD_TIME_COST`   | number | `3`     | Argon2 iterations        |
| `PASSWORD_PARALLELISM` | number | `4`     | Argon2 parallelism       |

### authEnvSchema

Authentication-specific configuration.

| Variable                   | Type   | Default  | Description               |
| -------------------------- | ------ | -------- | ------------------------- |
| `DEFAULT_REALM_NAME`       | string | `master` | Default realm name        |
| `REGISTRATION_RATE_LIMIT`  | number | `3`      | Max registrations/window  |
| `REGISTRATION_RATE_WINDOW` | number | `3600`   | Registration window (sec) |

### rateLimitEnvSchema

Global rate limiting configuration.

| Variable            | Type   | Default | Description             |
| ------------------- | ------ | ------- | ----------------------- |
| `RATE_LIMIT_MAX`    | number | `100`   | Max requests/window     |
| `RATE_LIMIT_WINDOW` | number | `3600`  | Rate limit window (sec) |

### jwtEnvSchema

EdDSA signing keys and token lifetimes (`JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`,
`JWT_ISSUER`, access/refresh lifespans).

### emailEnvSchema

Email provider selection and credentials (`EMAIL_PROVIDER` — `mock`, `resend` or
`smtp` — plus the provider-specific settings).

### observabilityEnvSchema

Log presentation, request-id propagation, the Prometheus `/metrics` surface, and
failed-login throttling: `LOG_PRETTY`, `REQUEST_ID_HEADER`, `METRICS_ENABLED`,
`FAILED_LOGIN_TRACKING_ENABLED`, `FAILED_LOGIN_MAX_ATTEMPTS`,
`FAILED_LOGIN_WINDOW`, `FAILED_LOGIN_LOCKOUT_DURATION`. (`LOG_LEVEL` itself lives
in `baseEnvSchema`.)

### cryptoEnvSchema

Post-quantum hybrid signing ([ADR-005](../../../docs/adr/005-pqc-hybrid-signing.md)).
**Off by default** — `SIGNING_ALGORITHM_MODE` is `ed25519` and
`HYBRID_SIGNING_ENABLED` is `false`.

| Variable                 | Type    | Default     | Description                                                                     |
| ------------------------ | ------- | ----------- | ------------------------------------------------------------------------------- |
| `SIGNING_ALGORITHM_MODE` | enum    | `ed25519`   | `ed25519` or `ed25519+ml-dsa-65`                                                |
| `HYBRID_SIGNING_ENABLED` | boolean | `false`     | Live hybrid issuance. Requires an ML-DSA key, or registration throws            |
| `JWT_MLDSA_PRIVATE_KEY`  | string  | —           | base64url 32-byte ML-DSA-65 seed (or `JWT_MLDSA_PRIVATE_KEY_PATH`)              |
| `JWT_MLDSA_KID`          | string  | —           | `kid` for the ML-DSA key published in JWKS                                      |
| `PQC_TOKEN_DELIVERY`     | enum    | `reference` | `reference` (introspection-first) or `self-contained`                           |
| `PQC_SELF_CONTAINED_ACK` | boolean | `false`     | Required to select `self-contained` — acknowledges the ~4.4 KB signature budget |

### federationEnvSchema

Wallet federation over OID4VP (T4, [ADR-004](../../../docs/adr/004-wallet-agnostic-federation.md)).
**Off by default** — with `WALLET_FEDERATION_ENABLED` unset the wallet routes are
never registered. Covers `OID4VP_VERIFIER_PROFILE`, `OID4VP_REQUESTED_VCT`,
`OID4VP_SUBJECT_RESOLUTION` and the subject-binding, status-list and
wallet-invocation settings. See the
[Docker guide](../../../docs/docker.md#wallet-federation-oid4vp-t4) for the full table.

### trustRegistryEnvSchema

The per-realm issuer allowlist (`OID4VP_TRUSTED_ISSUERS`). An issuer absent here
is refused before any claim is read.

### issuerKeysEnvSchema

The keys each trusted issuer signs with (`OID4VP_ISSUER_JWKS`).

### assuranceEnvSchema

Per-issuer eIDAS level of assurance (`OID4VP_ISSUER_ASSURANCE`), mapped to the
OIDC `acr` claim ([ADR-010](../../../docs/adr/010-acr-assurance-mapping.md)).
Listing an issuer here does **not** make it trusted — that is
`trustRegistryEnvSchema`'s job, and an issuer must appear in both.

## API

### parseEnv(schema)

Parses and validates environment variables against a Zod schema.

- Loads `.env` file using dotenv
- Validates `process.env` against the schema
- Returns a fully typed configuration object
- Throws `ZodError` if validation fails

```typescript
import { baseEnvSchema, parseEnv } from '@qauth-labs/server-config';

const env = parseEnv(baseEnvSchema);
```

## Type Exports

Each schema exports its corresponding TypeScript type:

```typescript
import type {
  AuthEnv,
  BaseEnv,
  DatabaseEnv,
  PasswordEnv,
  RateLimitEnv,
  RedisEnv,
} from '@qauth-labs/server-config';
```

## Error Handling

If required environment variables are missing or invalid, `parseEnv` throws a `ZodError` with detailed validation messages:

```typescript
import { ZodError } from 'zod';

try {
  const env = parseEnv(databaseEnvSchema);
} catch (error) {
  if (error instanceof ZodError) {
    console.error('Invalid environment configuration:', error.format());
    process.exit(1);
  }
}
```

## Best Practices

1. **Compose Only What You Need** - Only include schemas your app actually uses to avoid unnecessary validation overhead.

2. **Validate Early** - Call `parseEnv` at application startup to catch configuration errors immediately.

3. **Type Safety** - Use the exported types (`BaseEnv`, `DatabaseEnv`, etc.) for function parameters and return types.

4. **Environment-Specific Configs** - Create different schema compositions for different environments (development, production, test).

5. **Default Values** - Leverage Zod's `.default()` for optional configuration values with sensible defaults.

## Development

### Running Tests

```bash
nx test config
```

### Linting

```bash
nx lint config
```

## Dependencies

- `zod`: Schema validation and type inference
- `dotenv`: Environment variable loading

## Related Libraries

- [`@qauth-labs/server-password`](../password/README.md): Password hashing (uses `passwordEnvSchema`)
- [`@qauth-labs/server-jwt`](../jwt/README.md): JWT service (uses `jwtEnvSchema`)
- [`@qauth-labs/shared-validation`](../../shared/validation/README.md): Password validation (uses `passwordEnvSchema`)
- [`@qauth-labs/fastify-plugin-db`](../../fastify/plugins/db/README.md): Database plugin (uses `databaseEnvSchema`)
- [`@qauth-labs/fastify-plugin-cache`](../../fastify/plugins/cache/README.md): Cache plugin (uses `redisEnvSchema`)

## License

Apache-2.0
