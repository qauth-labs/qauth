// A regex-scanned fixture, never executed — `fastify` is typed loosely so
// this project (which doesn't depend on the real `fastify` package) still
// type-checks cleanly under `astro check`.
export default async function (fastify: { get: (path: string, handler: () => unknown) => void }) {
  fastify.get('/', async () => ({ ok: true }));
}
