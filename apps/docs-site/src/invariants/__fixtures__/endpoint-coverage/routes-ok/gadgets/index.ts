// autoPrefix override, mirroring apps/auth-server/src/app/routes/clients/index.ts.
export const autoPrefix = '/api/gadgets';

// See routes-ok/root.ts for why `fastify` is typed loosely here.
export default async function (fastify: { post: (path: string, handler: () => unknown) => void }) {
  fastify.post('/', async () => ({ created: true }));
}
