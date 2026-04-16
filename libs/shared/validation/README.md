# Validation Library

Password and email validation library with factory pattern for dependency injection. This library provides password strength validation and email format validation without direct `process.env` access.

## Overview

The `@qauth-labs/shared-validation` library provides:

- **Password strength validation** - Using zxcvbn algorithm with configurable minimum score
- **Email validation** - Format validation and normalization
- **Factory pattern** - Configuration-based instantiation (no `process.env` access for password validation)
- **Type-safe API** - Full TypeScript support
- **Testable** - Easy to inject mock configurations

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import {
  createPasswordValidator,
  DEFAULT_PASSWORD_VALIDATION_CONFIG,
  validateEmail,
} from '@qauth-labs/shared-validation';
```

## Usage

### Password Validation with Factory Pattern

```typescript
import {
  createPasswordValidator,
  DEFAULT_PASSWORD_VALIDATION_CONFIG,
} from '@qauth-labs/shared-validation';

// Create validator with default configuration
const validator = createPasswordValidator(DEFAULT_PASSWORD_VALIDATION_CONFIG);

// Validate password strength
const result = validator.validatePasswordStrength('mySecurePassword123');

if (!result.valid) {
  console.log('Password is too weak:', result.feedback);
  console.log('Score:', result.score); // 0-4
}
```

### Custom Password Validation Configuration

```typescript
import { createPasswordValidator } from '@qauth-labs/shared-validation';

// Create validator with custom minimum score
const strictValidator = createPasswordValidator({ minScore: 3 }); // Good minimum
const lenientValidator = createPasswordValidator({ minScore: 1 }); // Weak minimum

const result = strictValidator.validatePasswordStrength('password');
```

### Email Validation (Direct Function)

Email validation doesn't require configuration, so it's available as a direct function:

```typescript
import { validateEmail, normalizeEmail, isValidEmail } from '@qauth-labs/shared-validation';

// Validate and normalize email (throws if invalid)
try {
  const normalized = validateEmail('User@Example.com');
  // Returns: 'user@example.com'
} catch (error) {
  // Handle validation error
}

// Normalize email (no validation)
const normalized = normalizeEmail('User@Example.com');
// Returns: 'user@example.com'

// Check if email is valid (non-throwing)
if (isValidEmail('user@example.com')) {
  // Email is valid
}
```

### With Environment Configuration

```typescript
import { createPasswordValidator } from '@qauth-labs/shared-validation';
import { env } from '@qauth-labs/server-config';

// Use validated environment variables
const validator = createPasswordValidator({
  minScore: env.PASSWORD_MIN_SCORE,
});
```

## API

### Password Validation

#### `createPasswordValidator(config?: Partial<PasswordValidationConfig>): PasswordValidator`

Creates a password validator instance with the given configuration. Configuration is optional and partial - missing values will use defaults.

**Parameters**:

```typescript
interface PasswordValidationConfig {
  minScore?: number; // Minimum password strength score (0-4, default: 2)
}
```

**Returns**: `PasswordValidator` instance

**Throws**: `ZodError` if the configuration is invalid

#### `PasswordValidator` Interface

```typescript
interface PasswordValidator {
  /**
   * Validate password strength using zxcvbn
   * @param password - Password to validate
   * @returns Password strength validation result
   */
  validatePasswordStrength(password: string): PasswordStrengthResult;
}
```

#### `PasswordStrengthResult` Interface

```typescript
interface PasswordStrengthResult {
  valid: boolean; // Whether password meets minimum strength
  score: number; // Password strength score (0-4)
  feedback?: string[]; // Feedback messages from zxcvbn
  crackTimeSeconds?: number; // Estimated time to crack (seconds)
}
```

#### Password Strength Scores

- **0**: Very weak
- **1**: Weak
- **2**: Fair (default minimum)
- **3**: Good
- **4**: Strong

### Email Validation

#### `validateEmail(email: string): string`

Validates email format and returns normalized email. Throws `ZodError` if invalid.

**Parameters**:

- `email`: Email address to validate

**Returns**: Normalized email address (lowercase, trimmed)

**Throws**: `ZodError` if email format is invalid

#### `normalizeEmail(email: string): string`

Normalizes email address (lowercase, trimmed) without validation.

**Parameters**:

- `email`: Email address to normalize

**Returns**: Normalized email address

#### `isValidEmail(email: string): boolean`

Checks if email format is valid without throwing.

**Parameters**:

- `email`: Email address to check

**Returns**: `true` if email format is valid, `false` otherwise

### Constants

#### `DEFAULT_PASSWORD_VALIDATION_CONFIG`

Default password validation configuration:

```typescript
{
  minScore: 2, // Fair strength minimum
}
```

## Configuration

### Password Validation

- **minScore**: Minimum password strength score (0-4)
  - Default: `2` (Fair)
  - `0`: Very weak (not recommended)
  - `1`: Weak (not recommended)
  - `2`: Fair (recommended default)
  - `3`: Good (recommended for sensitive applications)
  - `4`: Strong (very strict)

### Environment Variables

When using with `@qauth-labs/server-config`, this environment variable is validated:

```bash
PASSWORD_MIN_SCORE=2  # Minimum password strength score (0-4)
```

## Examples

### Registration Flow

```typescript
import { createPasswordValidator, validateEmail } from '@qauth-labs/shared-validation';

const validator = createPasswordValidator(); // Uses defaults

async function registerUser(email: string, password: string) {
  // Validate and normalize email
  const normalizedEmail = validateEmail(email);

  // Validate password strength
  const strength = validator.validatePasswordStrength(password);
  if (!strength.valid) {
    throw new Error('Password is too weak: ' + strength.feedback?.join(', '));
  }

  // Create user with validated data
  await createUser({ email: normalizedEmail, password });
}
```

### Login Flow

```typescript
import { validateEmail, normalizeEmail } from '@qauth-labs/shared-validation';

async function loginUser(email: string, password: string) {
  // Normalize email for lookup (no validation needed for login)
  const normalizedEmail = normalizeEmail(email);

  // Find user by normalized email
  const user = await findUserByEmail(normalizedEmail);
  // ... rest of login logic
}
```

### Testing with Custom Configuration

```typescript
import { createPasswordValidator } from '@qauth-labs/shared-validation';

// Use lenient configuration for tests
const testValidator = createPasswordValidator({ minScore: 1 });

describe('Password validation', () => {
  it('should accept passwords meeting minimum score', () => {
    const result = testValidator.validatePasswordStrength('password123');
    expect(result.valid).toBe(true);
  });
});
```

## Migration from Direct Function Calls

If you're migrating from the old direct function calls:

**Before**:

```typescript
import { validatePasswordStrength, validateEmail } from '@qauth-labs/shared-validation';

const strength = validatePasswordStrength(password);
const email = validateEmail(email);
```

**After**:

```typescript
import { createPasswordValidator, validateEmail } from '@qauth-labs/shared-validation';

const validator = createPasswordValidator(); // Config is optional
const strength = validator.validatePasswordStrength(password);
const email = validateEmail(email); // Still direct function (no config needed)
```

## Security Considerations

1. **Password Strength**: Use appropriate `minScore` values based on your security requirements
2. **Email Normalization**: Always normalize emails before storing to prevent duplicate accounts
3. **Feedback Messages**: Provide user-friendly feedback from validation results
4. **Empty Passwords**: Empty passwords are automatically rejected (score 0)

## Development

### Running Tests

```bash
nx test validation
```

### Linting

```bash
nx lint validation
```

## Dependencies

- `zxcvbn`: Password strength estimation
- `zod`: Email format validation

## Related Libraries

- [`@qauth-labs/server-password`](../../server/password/README.md): Password hashing library
- [`@qauth-labs/server-config`](../../server/config/README.md): Environment configuration and validation
- [`@qauth-labs/fastify-plugin-password`](../../fastify/plugins/password/README.md): Fastify plugin for password services

## License

Apache-2.0
