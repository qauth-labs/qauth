# fastify-plugin-federation

Fastify plugin wrapping `@qauth-labs/server-federation` for the credential
provider registry.

## Usage

```typescript
import { federationPlugin } from '@qauth-labs/fastify-plugin-federation';
import { createPasswordProvider } from '@qauth-labs/server-federation';

await fastify.register(federationPlugin, {
  providers: [createPasswordProvider()],
});

// Resolve a provider by credential type in the auth engine
const provider = fastify.providerRegistry.resolve('password');
const identity = await provider.verify(input);
```

## Decorated Properties

- `fastify.providerRegistry.register(provider)` - Register a provider under its
  `type` (throws `ProviderAlreadyRegisteredError` on duplicates)
- `fastify.providerRegistry.resolve(type)` - Resolve the provider for a
  credential type (throws `ProviderNotRegisteredError` if missing)
- `fastify.providerRegistry.has(type)` - Whether a provider is registered for a
  credential type
