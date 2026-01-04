# Fastify Password Plugin

Fastify plugin for password hashing and validation in QAuth. This plugin provides dependency injection for password services using the factory pattern, eliminating direct `process.env` access.

## Overview

The `@qauth/fastify-plugin-password` plugin integrates password hashing and validation into your Fastify application by:

- Decorating the Fastify instance with `passwordHasher` and `passwordValidator` properties
- Using factory pattern for configuration (no direct `process.env` access)
- Providing type-safe password operations
- Enabling different password configurations per Fastify instance

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import { passwordPlugin } from '@qauth/fastify-plugin-password';
```

## Usage

### Basic Registration

```typescript
import Fastify from 'fastify';
import { passwordPlugin } from '@qauth/fastify-plugin-password';

const fastify = Fastify();

// Register the password plugin with default configuration (all configs optional)
await fastify.register(passwordPlugin);

// Or with partial configuration
await fastify.register(passwordPlugin, {
  hashConfig: {
    memoryCost: 65536, // Only override memoryCost, others use defaults
  },
  validationConfig: {
    minScore: 2, // Only override minScore
  },
});

// Start the server
await fastify.listen({ port: 3000 });
```

### With Environment Configuration

```typescript
import Fastify from 'fastify';
import { passwordPlugin } from '@qauth/fastify-plugin-password';
import { env } from '@qauth/server-config';

const fastify = Fastify();

// Register with environment-based configuration
await fastify.register(passwordPlugin, {
  hashConfig: {
    memoryCost: env.PASSWORD_MEMORY_COST,
    timeCost: env.PASSWORD_TIME_COST,
    parallelism: env.PASSWORD_PARALLELISM,
  },
  validationConfig: {
    minScore: env.PASSWORD_MIN_SCORE,
  },
});

await fastify.listen({ port: 3000 });
```

### Using Password Services in Routes

Once registered, both password hasher and validator are available on the Fastify instance:

```typescript
fastify.post('/register', async (request, reply) => {
  const { email, password } = request.body as { email: string; password: string };

  // Validate password strength
  const strength = fastify.passwordValidator.validatePasswordStrength(password);
  if (!strength.valid) {
    return reply.code(422).send({
      error: 'Weak password',
      feedback: strength.feedback,
    });
  }

  // Hash password
  const passwordHash = await fastify.passwordHasher.hashPassword(password);

  // Create user with hashed password
  const user = await createUser({ email, passwordHash });

  // Remove passwordHash from response
  const { passwordHash: _, ...safeUser } = user;
  return { user: safeUser };
});

fastify.post('/login', async (request, reply) => {
  const { email, password } = request.body as { email: string; password: string };

  const user = await findUserByEmail(email);
  if (!user) {
    return reply.code(401).send({ error: 'Invalid credentials' });
  }

  // Verify password
  const isValid = await fastify.passwordHasher.verifyPassword(user.passwordHash, password);

  if (!isValid) {
    return reply.code(401).send({ error: 'Invalid credentials' });
  }

  // Remove passwordHash from response
  const { passwordHash: _, ...safeUser } = user;
  return { user: safeUser };
});
```

## API

### Plugin Registration

```typescript
await fastify.register(passwordPlugin, options);
```

**Options**:

```typescript
interface PasswordPluginOptions {
  /**
   * Configuration for password hashing (Argon2)
   * All fields are optional - missing values will use defaults
   */
  hashConfig?: {
    memoryCost?: number; // Memory cost in KB (default: 65536 = 64MB)
    timeCost?: number; // Time cost / iterations (default: 3)
    parallelism?: number; // Parallelism / threads (default: 4)
  };
  /**
   * Configuration for password strength validation
   * All fields are optional - missing values will use defaults
   */
  validationConfig?: {
    minScore?: number; // Minimum password strength score 0-4 (default: 2 = Fair)
  };
}
```

**Note**: Both `hashConfig` and `validationConfig` are optional. If not provided, defaults will be used. Individual fields within each config are also optional.

### Fastify Instance Decorators

The plugin decorates the Fastify instance with two properties:

#### `fastify.passwordHasher`

Type: `PasswordHasher`

The password hasher instance with methods:

- `hashPassword(password: string): Promise<string>` - Hash a password using Argon2id
- `verifyPassword(hashedPassword: string, plainPassword: string): Promise<boolean>` - Verify a password against a hash

**Example**:

```typescript
// Hash a password
const hashed = await fastify.passwordHasher.hashPassword('mySecurePassword123');

// Verify a password
const isValid = await fastify.passwordHasher.verifyPassword(hashed, 'mySecurePassword123');
```

#### `fastify.passwordValidator`

Type: `PasswordValidator`

The password validator instance with methods:

- `validatePasswordStrength(password: string): PasswordStrengthResult` - Validate password strength using zxcvbn

**Example**:

```typescript
// Validate password strength
const result = fastify.passwordValidator.validatePasswordStrength('mySecurePassword123');

if (!result.valid) {
  console.log('Password is too weak:', result.feedback);
  console.log('Score:', result.score); // 0-4
  console.log('Crack time:', result.crackTimeSeconds, 'seconds');
}
```

## TypeScript Support

The plugin includes TypeScript type definitions. Both `fastify.passwordHasher` and `fastify.passwordValidator` are automatically typed:

```typescript
import { FastifyInstance } from 'fastify';

async function myRoute(fastify: FastifyInstance) {
  // TypeScript knows about fastify.passwordHasher and fastify.passwordValidator
  const hashed = await fastify.passwordHasher.hashPassword('password');
  const strength = fastify.passwordValidator.validatePasswordStrength('password');
}
```

## Configuration

### Environment Variables

The plugin accepts configuration through options. For environment-based configuration, use `@qauth/server-config`:

```typescript
import { env } from '@qauth/server-config';

await fastify.register(passwordPlugin, {
  hashConfig: {
    memoryCost: env.PASSWORD_MEMORY_COST,
    timeCost: env.PASSWORD_TIME_COST,
    parallelism: env.PASSWORD_PARALLELISM,
  },
  validationConfig: {
    minScore: env.PASSWORD_MIN_SCORE,
  },
});
```

Environment variables (validated by `@qauth/server-config`):

```bash
# Password hashing configuration (Argon2)
PASSWORD_MEMORY_COST=65536  # Memory cost in KB (default: 65536 = 64MB)
PASSWORD_TIME_COST=3        # Time cost / iterations (default: 3)
PASSWORD_PARALLELISM=4      # Parallelism / threads (default: 4)

# Password validation configuration
PASSWORD_MIN_SCORE=2        # Minimum strength score 0-4 (default: 2 = Fair)
```

### Password Strength Scores

- **0**: Very weak
- **1**: Weak
- **2**: Fair (default minimum)
- **3**: Good
- **4**: Strong

## Factory Pattern

This plugin uses the factory pattern from `@qauth/server-password` and `@qauth/shared-validation`:

- **No direct `process.env` access** - Configuration is passed explicitly
- **Testable** - Easy to inject mock configurations in tests
- **Flexible** - Different Fastify instances can use different configurations

```typescript
// Different configurations for different instances
const productionApp = Fastify();
await productionApp.register(passwordPlugin, {
  hashConfig: { memoryCost: 65536, timeCost: 3, parallelism: 4 },
  validationConfig: { minScore: 2 },
});

const testApp = Fastify();
await testApp.register(passwordPlugin, {
  hashConfig: { memoryCost: 32768, timeCost: 2, parallelism: 2 }, // Faster for tests
  validationConfig: { minScore: 1 }, // More lenient for tests
});
```

## Integration with Other Plugins

Register the password plugin after database and cache plugins:

```typescript
import { databasePlugin } from '@qauth/fastify-plugin-db';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { passwordPlugin } from '@qauth/fastify-plugin-password';
import { env } from '@qauth/server-config';

await fastify.register(databasePlugin, {
  config: {
    connectionString: env.DATABASE_URL,
    pool: {
      max: env.DB_POOL_MAX,
      min: env.DB_POOL_MIN,
      idleTimeoutMillis: env.DB_POOL_IDLE_TIMEOUT,
      connectionTimeoutMillis: env.DB_POOL_CONNECTION_TIMEOUT,
    },
  },
});
await fastify.register(cachePlugin, {
  config: {
    url: env.REDIS_URL,
    host: env.REDIS_HOST,
    port: env.REDIS_PORT,
    password: env.REDIS_PASSWORD,
    db: env.REDIS_DB,
    maxRetriesPerRequest: env.REDIS_MAX_RETRIES,
    connectTimeout: env.REDIS_CONNECTION_TIMEOUT,
    commandTimeout: env.REDIS_COMMAND_TIMEOUT,
    lazyConnect: true,
  },
});
await fastify.register(passwordPlugin, {
  hashConfig: {
    memoryCost: env.PASSWORD_MEMORY_COST,
    timeCost: env.PASSWORD_TIME_COST,
    parallelism: env.PASSWORD_PARALLELISM,
  },
  validationConfig: {
    minScore: env.PASSWORD_MIN_SCORE,
  },
});
```

## Error Handling

Password operations can throw errors:

```typescript
fastify.post('/register', async (request, reply) => {
  try {
    const passwordHash = await fastify.passwordHasher.hashPassword(password);
    // ...
  } catch (error) {
    fastify.log.error(error, 'Password hashing failed');
    reply.code(500).send({ error: 'Registration failed' });
  }
});
```

## Best Practices

1. **Register After Database/Cache**: Register the password plugin after database and cache plugins if you need them in your routes.

2. **Use Environment Configuration**: Use `@qauth/server-config` for environment-based configuration to ensure validation.

3. **Error Handling**: Always wrap password operations in try-catch blocks in production code.

4. **Never Return Password Hashes**: Always remove `passwordHash` from API responses. Use a helper function like `sanitizeUser()` to exclude sensitive fields.

5. **Password Strength**: Use appropriate `minScore` values based on your security requirements (2 = Fair is a good default).

6. **Argon2 Configuration**: Adjust `memoryCost`, `timeCost`, and `parallelism` based on your server capabilities and security requirements.

7. **Testing**: Use lower-cost configurations in tests for faster execution.

## Example: Complete Integration

```typescript
import Fastify from 'fastify';
import { databasePlugin } from '@qauth/fastify-plugin-db';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { passwordPlugin } from '@qauth/fastify-plugin-password';
import { env } from '@qauth/server-config';

const fastify = Fastify();

// Register plugins
await fastify.register(databasePlugin, {
  config: {
    connectionString: env.DATABASE_URL,
    pool: {
      max: env.DB_POOL_MAX,
      min: env.DB_POOL_MIN,
      idleTimeoutMillis: env.DB_POOL_IDLE_TIMEOUT,
      connectionTimeoutMillis: env.DB_POOL_CONNECTION_TIMEOUT,
    },
  },
});
await fastify.register(cachePlugin, {
  config: {
    url: env.REDIS_URL,
    host: env.REDIS_HOST,
    port: env.REDIS_PORT,
    password: env.REDIS_PASSWORD,
    db: env.REDIS_DB,
    maxRetriesPerRequest: env.REDIS_MAX_RETRIES,
    connectTimeout: env.REDIS_CONNECTION_TIMEOUT,
    commandTimeout: env.REDIS_COMMAND_TIMEOUT,
    lazyConnect: true,
  },
});
await fastify.register(passwordPlugin, {
  hashConfig: {
    memoryCost: env.PASSWORD_MEMORY_COST,
    timeCost: env.PASSWORD_TIME_COST,
    parallelism: env.PASSWORD_PARALLELISM,
  },
  validationConfig: {
    minScore: env.PASSWORD_MIN_SCORE,
  },
});

// Helper function to sanitize user data (remove sensitive fields)
function sanitizeUser(user: { passwordHash: string; [key: string]: unknown }) {
  const { passwordHash, ...safeUser } = user;
  return safeUser;
}

// Registration route
fastify.post('/auth/register', async (request, reply) => {
  const { email, password } = request.body as { email: string; password: string };

  // Validate password strength
  const strength = fastify.passwordValidator.validatePasswordStrength(password);
  if (!strength.valid) {
    return reply.code(422).send({
      error: 'Password does not meet strength requirements',
      feedback: strength.feedback,
    });
  }

  // Hash password
  const passwordHash = await fastify.passwordHasher.hashPassword(password);

  // Create user
  const user = await fastify.repositories.users.create({
    email,
    passwordHash,
    // ... other fields
  });

  // Remove passwordHash from response
  return reply.code(201).send({ user: sanitizeUser(user) });
});

// Login route
fastify.post('/auth/login', async (request, reply) => {
  const { email, password } = request.body as { email: string; password: string };

  const user = await fastify.repositories.users.findByEmail(email);
  if (!user) {
    return reply.code(401).send({ error: 'Invalid credentials' });
  }

  const isValid = await fastify.passwordHasher.verifyPassword(user.passwordHash, password);

  if (!isValid) {
    return reply.code(401).send({ error: 'Invalid credentials' });
  }

  // Remove passwordHash from response
  return { user: sanitizeUser(user) };
});

await fastify.listen({ port: 3000 });
```

## Development

### Running Tests

```bash
nx test fastify-plugin-password
```

### Linting

```bash
nx lint fastify-plugin-password
```

## Dependencies

- `@qauth/server-password`: Password hashing with factory pattern
- `@qauth/shared-validation`: Password validation with factory pattern
- `fastify-plugin`: Fastify plugin wrapper

## Related Libraries

- [`@qauth/server-password`](../../server/password/README.md): Password hashing library with factory pattern
- [`@qauth/shared-validation`](../../shared/validation/README.md): Password and email validation library
- [`@qauth/fastify-plugin-db`](../db/README.md): Database plugin for Fastify
- [`@qauth/fastify-plugin-cache`](../cache/README.md): Cache plugin for Fastify

## License

Apache-2.0
