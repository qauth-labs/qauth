// The back-channel logout delivery route's wiring (issue #624), and the
// protocol of `@qauth-labs/server-backchannel-logout` for the app, which may
// not import a server library itself.
export * from './lib/fastify-plugin-backchannel-logout';
export * from '@qauth-labs/server-backchannel-logout';
