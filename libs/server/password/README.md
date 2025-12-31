# Password Hashing Library

Password hashing library using Argon2id with factory pattern for dependency injection. This library provides secure password hashing without direct `process.env` access.

## Overview

The `@qauth/password` library provides:

- **Argon2id password hashing** - Industry-standard password hashing algorithm
- **Factory pattern** - Configuration-based instantiation (no `process.env` access)
- **Type-safe API** - Full TypeScript support
- **Testable** - Easy to inject mock configurations

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import { createPasswordHasher, DEFAULT_PASSWORD_CONFIG } from '@qauth/server-password';
```

## Usage

### Basic Usage with Factory Pattern

```typescript
import { createPasswordHasher } from '@qauth/server-password';

// Create hasher with default configuration (config is optional)
const hasher = createPasswordHasher();

// Hash a password
const hashed = await hasher.hashPassword('mySecurePassword123');

// Verify a password
const isValid = await hasher.verifyPassword(hashed, 'mySecurePassword123');
```

### Custom Configuration

```typescript
import { createPasswordHasher } from '@qauth/server-password';

// Create hasher with custom configuration
const hasher = createPasswordHasher({
  memoryCost: 32768, // 32MB (lower for faster hashing)
  timeCost: 2, // 2 iterations
  parallelism: 2, // 2 threads
});

const hashed = await hasher.hashPassword('password');
```

### With Environment Configuration

```typescript
import { createPasswordHasher } from '@qauth/server-password';
import { env } from '@qauth/server-config';

// Use validated environment variables
const hasher = createPasswordHasher({
  memoryCost: env.PASSWORD_MEMORY_COST,
  timeCost: env.PASSWORD_TIME_COST,
  parallelism: env.PASSWORD_PARALLELISM,
});
```

## API

### `createPasswordHasher(config?: Partial<PasswordHashConfig>): PasswordHasher`

Creates a password hasher instance with the given configuration. Configuration is optional and partial - missing values will use defaults.

**Parameters**:

```typescript
interface PasswordHashConfig {
  memoryCost?: number; // Memory cost in KB (default: 65536 = 64MB)
  timeCost?: number; // Time cost / iterations (default: 3)
  parallelism?: number; // Parallelism / threads (default: 4)
}
```

**Returns**: `PasswordHasher` instance

**Throws**: `ZodError` if the configuration is invalid

### `PasswordHasher` Interface

```typescript
interface PasswordHasher {
  /**
   * Hash a password using Argon2id
   * @param password - Plain text password to hash
   * @returns Hashed password string
   * @throws Error if hashing fails
   */
  hashPassword(password: string): Promise<string>;

  /**
   * Verify a password against a hash
   * @param hashedPassword - Previously hashed password string
   * @param plainPassword - Plain text password to verify
   * @returns True if password matches, false otherwise (including invalid hash format)
   */
  verifyPassword(hashedPassword: string, plainPassword: string): Promise<boolean>;
}
```

### Constants

#### `DEFAULT_PASSWORD_CONFIG`

Default password hashing configuration:

```typescript
{
  memoryCost: 65536, // 64MB
  timeCost: 3,
  parallelism: 4,
}
```

## Configuration

### Argon2 Parameters

- **memoryCost**: Memory cost in KB. Higher values increase security but require more memory.
  - Default: `65536` (64MB)
  - Minimum: `1` KB
  - Recommended: At least `8192` KB (8MB) for security

- **timeCost**: Number of iterations. Higher values increase security but take more time.
  - Default: `3`
  - Minimum: `1`
  - Maximum: `10` (higher values may cause performance issues)

- **parallelism**: Number of threads. Higher values can improve performance on multi-core systems.
  - Default: `4`
  - Minimum: `1`
  - Maximum: `255` (Argon2 specification limit)

### Environment Variables

When using with `@qauth/server-config`, these environment variables are validated:

```bash
PASSWORD_MEMORY_COST=65536  # Memory cost in KB
PASSWORD_TIME_COST=3        # Time cost / iterations
PASSWORD_PARALLELISM=4      # Parallelism / threads
```

## Examples

### Registration Flow

```typescript
import { createPasswordHasher } from '@qauth/server-password';

const hasher = createPasswordHasher(); // Uses defaults

async function registerUser(email: string, password: string) {
  // Hash password before storing
  const passwordHash = await hasher.hashPassword(password);

  // Store user with hashed password
  await createUser({ email, passwordHash });
}
```

### Login Flow

```typescript
import { createPasswordHasher } from '@qauth/server-password';

const hasher = createPasswordHasher(); // Uses defaults

async function loginUser(email: string, password: string) {
  const user = await findUserByEmail(email);
  if (!user) {
    throw new Error('User not found');
  }

  // Verify password
  const isValid = await hasher.verifyPassword(user.passwordHash, password);
  if (!isValid) {
    throw new Error('Invalid password');
  }

  // Remove passwordHash from response
  const { passwordHash: _, ...safeUser } = user;
  return safeUser;
}
```

### Testing with Custom Configuration

```typescript
import { createPasswordHasher } from '@qauth/server-password';

// Use lower-cost configuration for faster tests
const testHasher = createPasswordHasher({
  memoryCost: 16384, // 16MB (faster for tests)
  timeCost: 2, // 2 iterations
  parallelism: 2, // 2 threads
});

describe('Password hashing', () => {
  it('should hash and verify passwords', async () => {
    const password = 'testPassword123';
    const hashed = await testHasher.hashPassword(password);
    const isValid = await testHasher.verifyPassword(hashed, password);
    expect(isValid).toBe(true);
  });
});
```

## Security Considerations

1. **Never store plain text passwords** - Always hash passwords before storing
2. **Never return password hashes in API responses** - Always remove `passwordHash` from user objects before sending to clients
3. **Use appropriate configuration** - Higher `memoryCost` and `timeCost` values provide better security but may impact performance
4. **Handle errors** - Password hashing can fail; always wrap in try-catch blocks
5. **Invalid hash handling** - `verifyPassword` returns `false` for invalid hash formats (does not throw)

## Migration from Direct Function Calls

If you're migrating from the old direct function calls:

**Before**:

```typescript
import { hashPassword, verifyPassword } from '@qauth/server-password';

const hashed = await hashPassword(password);
const isValid = await verifyPassword(hashed, password);
```

**After**:

```typescript
import { createPasswordHasher } from '@qauth/server-password';

const hasher = createPasswordHasher(); // Config is optional
const hashed = await hasher.hashPassword(password);
const isValid = await hasher.verifyPassword(hashed, password);
```

## Development

### Running Tests

```bash
nx test password
```

### Linting

```bash
nx lint password
```

## Dependencies

- `@node-rs/argon2`: Fast Argon2 implementation in Rust (Node.js bindings)
- `zod`: Schema validation for configuration

## Related Libraries

- [`@qauth/shared-validation`](../validation/README.md): Password strength validation
- [`@qauth/fastify-plugin-password`](../../fastify/plugins/password/README.md): Fastify plugin for password services
- [`@qauth/server-config`](../config/README.md): Environment configuration and validation

## License

Apache-2.0
