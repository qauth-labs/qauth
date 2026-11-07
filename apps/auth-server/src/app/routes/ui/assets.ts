import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { uiAsset } from '../../helpers/ui-assets';

/**
 * THE /ui PAGES' STYLESHEET AND FONTS (#472): `GET /ui/assets/<file>`.
 *
 * Serves the files `helpers/ui-assets.ts` built when it loaded: the one
 * stylesheet every page links and the woff2 files it names. Each name carries
 * a hash of its content, so a cache may keep the answer for a year without
 * asking again (`immutable`); a new stylesheet or font comes under a new
 * name. A name outside the set is the app's 404, as an unknown path is: the
 * name is only a key of that set, never part of a path on disk.
 *
 * Not part of the API, so it is hidden from the OpenAPI document: only the
 * pages link these files, and their names change whenever a file does. The
 * path is a constant for the same reason as the admin listener's document
 * route; the docs site's endpoint-coverage guard, which reads paths written
 * as string literals, therefore does not list it either.
 *
 * A `browser` route, as every `/ui/*` route is: the files are fetched from
 * the page's own host, the realm's primary host.
 */

/** The route's path under the `/ui` prefix. */
const ASSET_PATH = '/assets/:file';

/** A year: the name changes with the content, so the answer never goes stale. */
const IMMUTABLE = 'public, max-age=31536000, immutable';

export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    ASSET_PATH,
    {
      schema: {
        hide: true,
        params: z.object({ file: z.string() }),
      },
      config: { surface: 'browser' },
    },
    async (request, reply) => {
      const asset = uiAsset(request.params.file);
      if (asset === undefined) return reply.callNotFound();
      reply.header('Content-Type', asset.contentType);
      reply.header('Cache-Control', IMMUTABLE);
      return reply.send(asset.body);
    }
  );
}
