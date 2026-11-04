import { createRedisSendCaps, type MailPassFlow } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { ceremonyPagePath, stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { html, render } from '../../helpers/html';
import { startMailedPassInteraction } from '../../helpers/interaction';
import type { InteractionStep } from '../../helpers/interaction-record';
import { requestRealm } from '../../helpers/request-realm';

/**
 * The landing of a mailed pass link: `GET /auth/pass?pass=…` (#637, ADR-017
 * Decision 5).
 *
 * The send-ceiling and password-disabled notices carry a link with a
 * single-use 256-bit pass, bound to the address it was mailed to and valid
 * 24 hours, which takes one reset or registration start past every
 * per-address send tier. Opening the link starts an interaction of purpose
 * `mailed_pass` in this browser, with a flow cookie of its own, puts the
 * pass's hash in it, and redirects to the ceremony page with the interaction
 * id and nothing else. A reset starts at `password_reset`, a registration at
 * `identifier`.
 *
 * Opening the link never spends the pass: it is only read here, and the
 * start it carries spends it (the send caps' reserve). So a mail gateway's
 * link scanner or a browser prefetch that opens the link spends nothing, and
 * opening it twice starts two interactions that hold the same pass, of which
 * one start can use it. The mailed code is still required.
 *
 * A pass that is malformed, unknown, used, expired or another realm's gets
 * one page, and no interaction. The pass never leaves this answer another
 * way: `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and the
 * request log censors the `pass` query value (`LOG_REDACTED_QUERY_PARAMETERS`).
 *
 * A `browser` route: it sets the flow cookie, so it answers on the realm's
 * primary host only.
 */

/** The first step of the start a pass carries. */
function firstStep(flow: MailPassFlow): InteractionStep {
  return {
    name: stepUrn(flow === 'reset' ? 'password_reset' : 'identifier'),
    params: {},
    alternatives: [],
  };
}

/** The page of a link whose pass opens nothing, whatever the reason. */
function sendInvalidPassPage(reply: FastifyReply): FastifyReply {
  const title = 'This link is no longer valid';
  const page = render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>${title} — QAuth</title>
        </head>
        <body>
          <main>
            <h1>${title}</h1>
            <p>
              The link has expired, has already been used, or is incomplete. You can still reset
              your password or create an account from the sign-in page.
            </p>
          </main>
        </body>
      </html>`
  );
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  reply.header('Referrer-Policy', 'no-referrer');
  return reply.code(400).send(page);
}

export default async function (fastify: FastifyInstance) {
  const caps = createRedisSendCaps(fastify.redis);

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/pass',
    {
      schema: {
        description:
          'Landing page of a mailed pass link (the send-ceiling and password-disabled notices). Starts an interaction that holds the pass and redirects (303) to its ceremony page; opening it does not spend the pass. A malformed, unknown, used or expired pass gets an HTML page and no interaction.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        querystring: z.object({
          // Checked in the handler, not here: a damaged link gets the page
          // rather than a problem document, and the value is not echoed back.
          pass: z.string().optional(),
        }),
      },
      config: { surface: 'browser' },
    },
    async (request, reply) => {
      const { pass } = request.query as { pass?: string };
      const binding =
        pass === undefined ? undefined : await caps.peekPass(requestRealm(request).id, pass);
      if (binding === undefined) return sendInvalidPassPage(reply);

      const started = await startMailedPassInteraction(request, reply, {
        request: { flow: binding.flow, passHash: binding.passHash },
        step: firstStep(binding.flow),
      });
      reply.header('Cache-Control', 'no-store');
      reply.header('Referrer-Policy', 'no-referrer');
      return reply.redirect(ceremonyPagePath(started.id), 303);
    }
  );
}
