// The AuthMethod contract (#599): EXPERIMENTAL, the plugin API of ADR-018 §4.
// It may change in a minor release.
//
// The contract is declared once, in `@qauth-labs/plugin-sdk` (#1009), the
// package a plugin is written against in its own repository. The server
// re-exports it here, for the libraries and the app that reach the contract
// through this one, and declares none of it again (`single-copy.test.ts`).
export * from '@qauth-labs/plugin-sdk';
export * from '@qauth-labs/plugin-sdk/host';

// The server's own: the registry item, the generic OIDC client's reserved
// names, the plugin loader and the secret members of a plugin's config.
export * from './contract';
export * from './plugin-loader';
export * from './secret-members';
