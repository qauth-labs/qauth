# Email Library

Email service library for QAuth with token generation utilities. This library provides secure token generation and a flexible email service with provider abstraction.

## Overview

The `@qauth/email` library provides:

- **Token Generator**: Secure token generation and verification utilities
- **Email Service**: Factory-pattern email service with provider abstraction
- **Mock Provider**: Testing provider for development and testing

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import { generateVerificationToken, createEmailService } from '@qauth/server-email';
```

## Token Generator

### generateVerificationToken()

Generates a secure verification token pair (token and hash).

```typescript
import { generateVerificationToken } from '@qauth/server-email';

const { token, tokenHash } = generateVerificationToken();
// token: "a1b2c3d4e5f6..." (64 chars, send to user)
// tokenHash: "9f8e7d6c5b4a..." (64 chars, store in DB)
```

**Security Features**:

- 32-byte (256-bit) random tokens using `crypto.randomBytes(32)`
- Hex encoding (64 characters) for URL-safe transmission
- SHA-256 hashing for secure storage
- High entropy prevents brute-force attacks

### hashToken(token)

Hashes a token using SHA-256 before storing in the database.

```typescript
import { hashToken } from '@qauth/server-email';

const hash = hashToken('a1b2c3d4e5f6...');
// Returns: "9f8e7d6c5b4a..." (SHA-256 hash)
```

### isValidTokenFormat(token)

Validates that a token is a valid 64-character hexadecimal string.

```typescript
import { isValidTokenFormat } from '@qauth/server-email';

isValidTokenFormat('a1b2c3d4e5f6...'); // true (64 hex chars)
isValidTokenFormat('invalid'); // false (too short)
```

### constantTimeCompare(token1, token2)

Compares two tokens in constant time to prevent timing attacks.

```typescript
import { constantTimeCompare } from '@qauth/server-email';

const isValid = constantTimeCompare(storedToken, providedToken);
```

**Security**: Uses `crypto.timingSafeEqual` to prevent timing attacks.

## Email Service

### Factory Pattern

The email service uses a factory pattern for dependency injection:

```typescript
import { createEmailService, createMockEmailProvider } from '@qauth/server-email';

const provider = createMockEmailProvider();
const emailService = createEmailService(provider, {
  defaultFrom: 'noreply@example.com',
  baseUrl: 'https://example.com',
});
```

### sendVerificationEmail()

Sends a verification email with a token.

```typescript
await emailService.sendVerificationEmail('user@example.com', 'token123');
```

With custom options:

```typescript
await emailService.sendVerificationEmail('user@example.com', 'token123', {
  subject: 'Custom Subject',
  from: 'custom@example.com',
  text: 'Custom text',
  html: '<p>Custom HTML</p>',
});
```

### Email Provider Interface

The email service is built on a provider abstraction, making it verification-agnostic and reusable for other email types (password reset, notifications, etc.):

```typescript
interface EmailProvider {
  sendEmail(options: EmailOptions): Promise<EmailResult>;
}
```

### Mock Provider

For testing and development:

```typescript
import { createMockEmailProvider } from '@qauth/server-email';

const provider = createMockEmailProvider();
await provider.sendEmail({
  to: 'user@example.com',
  subject: 'Test',
  text: 'Body',
});

// Get sent emails for testing
const sentEmails = provider.getSentEmails();
console.log(sentEmails);

// Clear history
provider.clearSentEmails();
```

## API Reference

### Token Generator

#### `generateVerificationToken(): TokenPair`

Generates a secure token pair.

**Returns**: `{ token: string, tokenHash: string }`

#### `hashToken(token: string): string`

Hashes a token using SHA-256.

**Parameters**:

- `token`: Plain token string to hash

**Returns**: SHA-256 hash (64-character hex string)

#### `isValidTokenFormat(token: string): boolean`

Validates token format.

**Parameters**:

- `token`: Token string to validate

**Returns**: `true` if valid, `false` otherwise

#### `constantTimeCompare(token1: string, token2: string): boolean`

Compares tokens in constant time.

**Parameters**:

- `token1`: First token
- `token2`: Second token

**Returns**: `true` if tokens match, `false` otherwise

### Email Service

#### `createEmailService(provider: EmailProvider, config?: EmailServiceConfig): EmailService`

Creates an email service instance.

**Parameters**:

- `provider`: Email provider implementation
- `config`: Optional service configuration

**Returns**: Email service instance

#### `emailService.sendVerificationEmail(to: string, token: string, options?: Partial<EmailOptions>): Promise<EmailResult>`

Sends a verification email.

**Parameters**:

- `to`: Recipient email address
- `token`: Verification token
- `options`: Optional email options

**Returns**: Promise resolving to email result

## Security Considerations

### Token Generation

- **High Entropy**: 32 bytes (256 bits) of random data
- **Secure Random**: Uses `crypto.randomBytes(32)` (CVE-2023-2781 mitigation)
- **Hashing**: Tokens are hashed before storage (SHA-256)
- **Constant-Time Comparison**: Prevents timing attacks

### Token Storage

- **Never store plain tokens**: Always store the hash (`tokenHash`)
- **Send plain token to user**: Include the plain `token` in the verification email
- **Compare hashes**: When verifying, hash the provided token and compare with stored hash

### Example: Token Verification Flow

```typescript
import { generateVerificationToken, hashToken, constantTimeCompare } from '@qauth/server-email';

// 1. Generate token on registration
const { token, tokenHash } = generateVerificationToken();
// Store tokenHash in database
await db.emailVerificationTokens.create({ tokenHash, userId, expiresAt });

// 2. Send token to user
await emailService.sendVerificationEmail(user.email, token);

// 3. Verify token when user clicks link
const providedToken = request.query.token;
const storedTokenHash = await db.emailVerificationTokens.findByTokenHash(tokenHash);

// Hash the provided token and compare
const providedTokenHash = hashToken(providedToken);
const isValid = constantTimeCompare(storedTokenHash, providedTokenHash);
```

## Testing

Run tests:

```bash
nx test server-email
```

## Type Exports

```typescript
import type {
  TokenPair,
  EmailProvider,
  EmailService,
  EmailOptions,
  EmailResult,
  EmailServiceConfig,
} from '@qauth/server-email';
```

## Related Libraries

- [`@qauth/fastify-plugin-email`](../../fastify/plugins/email/README.md): Fastify plugin for email service
- [`@qauth/password`](../password/README.md): Password hashing library
- [`@qauth/shared-validation`](../../shared/validation/README.md): Email validation utilities

## License

Apache-2.0
