# Fastify Email Plugin

Fastify plugin for email service in QAuth. This plugin provides dependency injection for email services using the factory pattern, eliminating direct `process.env` access.

## Overview

The `@qauth/fastify-plugin-email` plugin integrates email functionality into your Fastify application by:

- Decorating the Fastify instance with `emailService` property
- Using factory pattern for configuration (no direct `process.env` access)
- Providing type-safe email operations
- Supporting multiple email providers (mock, resend, smtp)
- Enabling different email configurations per Fastify instance

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import { emailPlugin } from '@qauth/fastify-plugin-email';
```

## Usage

### Basic Registration

```typescript
import Fastify from 'fastify';
import { emailPlugin } from '@qauth/fastify-plugin-email';

const fastify = Fastify();

// Register the email plugin with mock provider (default)
await fastify.register(emailPlugin);

// Or explicitly specify provider
await fastify.register(emailPlugin, {
  provider: 'mock',
});

// Start the server
await fastify.listen({ port: 3000 });
```

### With Service Configuration

```typescript
import Fastify from 'fastify';
import { emailPlugin } from '@qauth/fastify-plugin-email';

const fastify = Fastify();

// Register with service configuration
await fastify.register(emailPlugin, {
  provider: 'mock',
  serviceConfig: {
    defaultFrom: 'noreply@example.com',
    baseUrl: 'https://example.com',
  },
});

await fastify.listen({ port: 3000 });
```

### Using Email Service in Routes

Once registered, the email service is available on the Fastify instance:

```typescript
fastify.post('/auth/register', async (request, reply) => {
  const { email, password } = request.body as { email: string; password: string };

  // Create user
  const user = await createUser({ email, password });

  // Generate verification token
  const { token, tokenHash } = generateVerificationToken();

  // Store token hash in database
  await db.emailVerificationTokens.create({
    tokenHash,
    userId: user.id,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
  });

  // Send verification email
  await fastify.emailService.sendVerificationEmail(email, token);

  return reply.code(201).send({
    user: { id: user.id, email: user.email },
    message: 'Registration successful. Please check your email to verify your account.',
  });
});
```

## API

### Plugin Registration

```typescript
await fastify.register(emailPlugin, options);
```

**Options**:

```typescript
interface EmailPluginOptions {
  /**
   * Email provider type (mock, resend, smtp)
   * Default: 'mock'
   */
  provider?: 'mock' | 'resend' | 'smtp';
  /**
   * Provider-specific configuration
   * Optional - depends on provider type
   */
  providerConfig?: EmailProviderConfig;
  /**
   * Email service configuration
   * Optional - missing values will use defaults
   */
  serviceConfig?: {
    /**
     * Default sender email address
     */
    defaultFrom?: string;
    /**
     * Base URL for verification links
     */
    baseUrl?: string;
  };
}
```

**Note**: Both `providerConfig` and `serviceConfig` are optional. If not provided, defaults will be used.

### Fastify Instance Decorators

The plugin decorates the Fastify instance with one property:

#### `fastify.emailService`

Type: `EmailService`

The email service instance with methods:

- `sendVerificationEmail(to: string, token: string, options?: Partial<EmailOptions>): Promise<EmailResult>` - Send a verification email

**Example**:

```typescript
// Send verification email
const result = await fastify.emailService.sendVerificationEmail('user@example.com', 'token123');

if (result.success) {
  console.log('Email sent:', result.messageId);
} else {
  console.error('Email failed:', result.error);
}
```

## TypeScript Support

The plugin includes TypeScript type definitions. `fastify.emailService` is automatically typed:

```typescript
import { FastifyInstance } from 'fastify';

async function myRoute(fastify: FastifyInstance) {
  // TypeScript knows about fastify.emailService
  await fastify.emailService.sendVerificationEmail('user@example.com', 'token123');
}
```

## Email Providers

### Mock Provider (Default)

The mock provider logs emails to the console and stores them in memory. Useful for development and testing:

```typescript
await fastify.register(emailPlugin, {
  provider: 'mock',
});
```

**Features**:

- No external dependencies
- Logs emails to console (in non-test environments)
- Stores emails in memory for testing
- Always succeeds

### Resend Provider (Future)

The Resend provider will send emails via the Resend API:

```typescript
await fastify.register(emailPlugin, {
  provider: 'resend',
  providerConfig: {
    apiKey: 're_...',
  },
});
```

**Status**: Not yet implemented

### SMTP Provider (Future)

The SMTP provider will send emails via SMTP:

```typescript
await fastify.register(emailPlugin, {
  provider: 'smtp',
  providerConfig: {
    host: 'smtp.example.com',
    port: 587,
    secure: false,
    auth: {
      user: 'user@example.com',
      pass: 'password',
    },
  },
});
```

**Status**: Not yet implemented

## Configuration

### Environment Variables

The plugin accepts configuration through options. For environment-based configuration, you can extend `@qauth/server-config`:

```typescript
import { env } from '@qauth/server-config';

await fastify.register(emailPlugin, {
  provider: env.EMAIL_PROVIDER || 'mock',
  serviceConfig: {
    defaultFrom: env.EMAIL_FROM,
    baseUrl: env.EMAIL_BASE_URL,
  },
});
```

**Note**: Email environment variables are not yet defined in `@qauth/server-config`. This can be added in a future update.

## Factory Pattern

This plugin uses the factory pattern from `@qauth/server-email`:

- **No direct `process.env` access** - Configuration is passed explicitly
- **Testable** - Easy to inject mock configurations in tests
- **Flexible** - Different Fastify instances can use different configurations

```typescript
// Different configurations for different instances
const productionApp = Fastify();
await productionApp.register(emailPlugin, {
  provider: 'resend',
  serviceConfig: {
    defaultFrom: 'noreply@example.com',
    baseUrl: 'https://example.com',
  },
});

const testApp = Fastify();
await testApp.register(emailPlugin, {
  provider: 'mock', // Use mock for tests
});
```

## Integration with Other Plugins

Register the email plugin after database and password plugins:

```typescript
import { databasePlugin } from '@qauth/fastify-plugin-db';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { passwordPlugin } from '@qauth/fastify-plugin-password';
import { emailPlugin } from '@qauth/fastify-plugin-email';

await fastify.register(databasePlugin);
await fastify.register(cachePlugin);
await fastify.register(passwordPlugin);
await fastify.register(emailPlugin, {
  provider: 'mock',
  serviceConfig: {
    /* ... */
  },
});
```

## Error Handling

Email operations can fail. Always handle errors:

```typescript
fastify.post('/auth/register', async (request, reply) => {
  try {
    const result = await fastify.emailService.sendVerificationEmail(email, token);
    if (!result.success) {
      fastify.log.error({ error: result.error }, 'Email sending failed');
      // Handle error (e.g., queue for retry, log, etc.)
    }
  } catch (error) {
    fastify.log.error(error, 'Email service error');
    reply.code(500).send({ error: 'Registration failed' });
  }
});
```

## Best Practices

1. **Register After Database/Password**: Register the email plugin after database and password plugins if you need them in your routes.

2. **Use Mock Provider for Tests**: Use the mock provider in test environments to avoid external dependencies.

3. **Error Handling**: Always wrap email operations in try-catch blocks in production code.

4. **Logging**: The plugin logs debug information when registered. Check logs to verify plugin registration.

5. **Provider Selection**: Choose the appropriate provider based on your environment:
   - Development: `mock`
   - Testing: `mock`
   - Production: `resend` or `smtp` (when implemented)

6. **Configuration**: Use environment-based configuration for production deployments.

## Example: Complete Integration

```typescript
import Fastify from 'fastify';
import { databasePlugin } from '@qauth/fastify-plugin-db';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { passwordPlugin } from '@qauth/fastify-plugin-password';
import { emailPlugin } from '@qauth/fastify-plugin-email';
import { generateVerificationToken } from '@qauth/server-email';

const fastify = Fastify();

// Register plugins
await fastify.register(databasePlugin);
await fastify.register(cachePlugin);
await fastify.register(passwordPlugin);
await fastify.register(emailPlugin, {
  provider: 'mock', // Use 'resend' or 'smtp' in production
  serviceConfig: {
    defaultFrom: 'noreply@example.com',
    baseUrl: 'https://example.com',
  },
});

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

  // Generate verification token
  const { token, tokenHash } = generateVerificationToken();

  // Store token hash in database
  await fastify.repositories.emailVerificationTokens.create({
    tokenHash,
    userId: user.id,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
  });

  // Send verification email
  try {
    const result = await fastify.emailService.sendVerificationEmail(email, token);
    if (!result.success) {
      fastify.log.error({ error: result.error }, 'Failed to send verification email');
    }
  } catch (error) {
    fastify.log.error(error, 'Error sending verification email');
  }

  // Remove passwordHash from response
  const { passwordHash: _, ...safeUser } = user;
  return reply.code(201).send({ user: safeUser });
});

await fastify.listen({ port: 3000 });
```

## Development

### Running Tests

```bash
nx test fastify-plugin-email
```

### Linting

```bash
nx lint fastify-plugin-email
```

## Dependencies

- `@qauth/server-email`: Email service library with factory pattern
- `fastify-plugin`: Fastify plugin wrapper

## Related Libraries

- [`@qauth/server-email`](../../server/email/README.md): Email service library with factory pattern
- [`@qauth/fastify-plugin-db`](../db/README.md): Database plugin for Fastify
- [`@qauth/fastify-plugin-password`](../password/README.md): Password plugin for Fastify

## License

Apache-2.0
