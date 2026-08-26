// Directory-derived prefix (no autoPrefix export): serves under /widgets.
// See routes-ok/root.ts for why `fastify` is typed loosely here.
export default async function (fastify: { get: (path: string, handler: () => unknown) => void }) {
  fastify.get('/', async () => ({ widgets: [] }));
  fastify.get('/:id', async () => ({ id: 'x' }));
}
