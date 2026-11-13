import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import {
  ACCOUNT_PAGE_CHANGES,
  accountCsrfAccepted,
  accountCsrfToken,
  type AccountPageChange,
  changePassword,
  checkFreshAuthentication,
  type CredentialTarget,
  endAccountSession,
  endAllAccountSessions,
  readAccountOverview,
  regenerateRecoveryCodes,
  removeCredential,
  renamePasskey,
} from '../../helpers/account-changes';
import { accountCeremonies, type AccountCeremony } from '../../helpers/account-interaction';
import {
  ACCOUNT_NOTICES,
  ACCOUNT_PAGE_PATH,
  accountMessagePage,
  type AccountNotice,
  accountPage,
  CURRENT_PASSWORD_REFUSED,
  newRecoveryCodesPage,
  passwordChangePage,
  reauthenticatePage,
} from '../../helpers/account-pages';
import { createBackgroundTasks } from '../../helpers/background-tasks';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { ACCOUNT_RETURN_PATHS, type AccountReturnPath } from '../../helpers/interaction-record';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import { buildRealmUrl, realmIssuer } from '../../helpers/realm-url';
import { requestRealm } from '../../helpers/request-realm';
import { clearSessionCookie } from '../../helpers/session-cookie';
import { unlinkUpstreamIdentity } from '../../helpers/upstream-links';
import { emitUserEvent } from '../../helpers/user-events';

/**
 * THE HOSTED ACCOUNT PAGES, `/ui/account` (#844; ADR-017 Decision 8, ADR-020
 * §3): a signed-in person's sign-in methods, password, passkeys,
 * authenticator app, recovery codes, linked upstream accounts and sessions,
 * server-rendered in the current `/ui` style until the design-system
 * account console (#684–#688) replaces them.
 *
 *   GET  /ui/account                                   — the overview
 *   GET  /ui/account/password                          — the password form
 *   POST /ui/account/password                          — change the password
 *   POST /ui/account/reauthenticate                    — confirm it's you
 *   POST /ui/account/passkeys/add                      — add a passkey
 *   POST /ui/account/passkeys/{passkeyId}/rename       — rename one
 *   POST /ui/account/passkeys/{passkeyId}/remove       — remove one
 *   POST /ui/account/totp/setup                        — set up an authenticator app
 *   POST /ui/account/totp/remove                       — turn it off
 *   POST /ui/account/recovery-codes/regenerate         — a new set, shown once
 *   POST /ui/account/recovery-codes/confirm            — the set is saved
 *   POST /ui/account/sessions/{sessionId}/end          — sign one session out
 *   POST /ui/account/sessions/end-all                  — sign out everywhere
 *   POST /ui/account/linked-accounts/link              — link an upstream account
 *   POST /ui/account/linked-accounts/{linkedAccountId}/unlink — unlink one
 *
 * The pages are reached with the realm's browser session: a page opened
 * without one starts a sign-in on the hosted pages and comes back
 * (`account-interaction.ts`). They exist while the hosted pages do
 * (`INTERACTION_UI_ENABLED`, ADR-017: "the reset, verification and account
 * pages are on whenever hosted pages are on"); otherwise no route is
 * registered, and each is experimental: the console removes them.
 *
 * Every form post is checked in this order, before anything is read or
 * changed: it comes from the realm's origin (`Sec-Fetch-Site`, or `Origin`
 * when the browser sends no fetch metadata); it carries the browser session,
 * or it goes to the overview, which signs the person in; it carries the
 * session's account CSRF value (`request.csrf_rejected` otherwise); and a
 * change that asks for a fresh authentication has one
 * (`checkFreshAuthentication`), or the person is asked to sign in again.
 * Adding a passkey, setting up an authenticator app and linking an upstream
 * account need no check of their own: each is a fresh sign-in first.
 *
 * A change answers with a redirect to the overview and its notice (`303`); a
 * refusal with its page and its status. Nothing sends a secret or a code in
 * a URL, and every page is `Cache-Control: no-store`.
 */

const NOTICES = Object.keys(ACCOUNT_NOTICES) as AccountNotice[];

const csrfBody = { csrf: z.string().max(256).optional() };

/** Whether a request comes from a page of the realm's origin, as the Interaction API checks it. */
function fromRealmOrigin(request: FastifyRequest): boolean {
  const site = request.headers['sec-fetch-site'];
  if (site !== undefined) return site === 'same-origin';
  return request.headers.origin === new URL(realmIssuer(requestRealm(request))).origin;
}

export default async function (fastify: FastifyInstance) {
  // ADR-017: the account pages are on whenever the hosted pages are.
  if (env.INTERACTION_UI_ENABLED !== true) return;

  const app = fastify.withTypeProvider<ZodTypeProvider>();
  // The engines' mail registers a hook, so its tasks are made here.
  const ceremonies = accountCeremonies(fastify, createBackgroundTasks(fastify));

  // The authorization endpoint's budget: each page is one step of a person's
  // own account, as each sign-in page is.
  const config = {
    surface: 'browser' as const,
    rateLimit: {
      max: (request: FastifyRequest) =>
        resolveRealmRateLimitMax(request.realm, {
          lenientMax: env.AUTHORIZE_RATE_LIMIT_LENIENT,
          strictMax: env.AUTHORIZE_RATE_LIMIT,
        }),
      timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
      keyGenerator: realmRateLimitKey,
    },
  };
  const tags = ['UI'];

  const sendPage = (reply: FastifyReply, body: string, status = 200) =>
    reply
      .code(status)
      .header('Cache-Control', 'no-store')
      .header('Content-Type', 'text/html; charset=utf-8')
      .send(body);
  const message = (
    reply: FastifyReply,
    status: number,
    title: string,
    text: string,
    back?: { readonly href: string; readonly label: string }
  ) =>
    sendPage(
      reply,
      accountMessagePage({
        cspNonce: reply.cspNonce.style,
        title,
        message: text,
        ...(back === undefined ? {} : { back }),
      }),
      status
    );
  const notFound = (reply: FastifyReply) =>
    message(reply, 404, 'Not found', 'That is not part of your account any more.');
  /** The overview on the realm's origin, with a notice. */
  const overviewUrl = (request: FastifyRequest, notice?: AccountNotice) =>
    buildRealmUrl(
      requestRealm(request),
      notice === undefined ? ACCOUNT_PAGE_PATH : `${ACCOUNT_PAGE_PATH}?notice=${notice}`
    );
  /** Start a ceremony of the account page and send the browser to it. */
  const startCeremony = async (
    request: FastifyRequest,
    reply: FastifyReply,
    ceremony: AccountCeremony
  ) => reply.redirect(await ceremonies.start(request, reply, ceremony), 303);
  const carried = (session: BrowserSession) => ({ userId: session.userId, sid: session.sid });

  /**
   * The checks of every form post, in order; `null` when the post was
   * answered by one of them.
   */
  const admitted = async (
    request: FastifyRequest,
    reply: FastifyReply,
    csrf: string | undefined,
    change?: AccountPageChange,
    returnTo: AccountReturnPath = ACCOUNT_PAGE_PATH,
    removing?: CredentialTarget
  ): Promise<BrowserSession | null> => {
    if (!fromRealmOrigin(request)) {
      request.log.info({ accountRefused: 'origin' }, 'account page post forbidden');
      await emitUserEvent(
        request,
        'urn:qauth:event:request.csrf_rejected:v1-rc.0',
        { form: 'account' },
        { actor: 'user' }
      );
      await message(reply, 403, 'Not allowed', 'This request did not come from this site.');
      return null;
    }
    const session = await resolveBrowserSession(fastify, request, reply);
    if (session === null) {
      // No change without a session: the overview signs the person in.
      await reply.redirect(overviewUrl(request), 303);
      return null;
    }
    if (!(await accountCsrfAccepted(fastify, request, session, csrf))) {
      await message(
        reply,
        403,
        'Not allowed',
        'This form has expired. Go back to your account and try again.'
      );
      return null;
    }
    if (change !== undefined) {
      const verdict = await checkFreshAuthentication(
        fastify,
        request,
        session,
        change,
        Date.now(),
        removing
      );
      if (verdict.kind === 'refused') {
        await sendPage(
          reply,
          reauthenticatePage({
            cspNonce: reply.cspNonce.style,
            csrf: await accountCsrfToken(fastify, session),
            requiredFactor: verdict.requiredFactor,
            returnTo,
          }),
          403
        );
        return null;
      }
    }
    return session;
  };

  app.get(
    '/account',
    {
      schema: {
        description:
          'The hosted account page (#844): the browser session’s account, its sign-in methods (password, passkeys, authenticator app, recovery codes, linked upstream accounts) and its live sessions, each with its actions as plain forms. A browser with no session is sent through a sign-in on the hosted pages (`303`) and comes back. Replaced by the account console (#685–#688). `Cache-Control: no-store`.',
        tags,
        'x-qauth-stability': 'experimental',
        querystring: z.object({ notice: z.string().max(64).optional() }),
      },
      config,
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (session === null) {
        return startCeremony(request, reply, { intent: 'sign_in', returnTo: ACCOUNT_PAGE_PATH });
      }
      const notice = NOTICES.find((name) => name === request.query.notice);
      const overview = await readAccountOverview(fastify, ceremonies.engines(), session);
      return sendPage(
        reply,
        accountPage({
          cspNonce: reply.cspNonce.style,
          csrf: await accountCsrfToken(fastify, session),
          overview,
          passkeysOn: fastify.passkeySignIn === true,
          ...(notice === undefined ? {} : { notice }),
        })
      );
    }
  );

  app.get(
    '/account/password',
    {
      schema: {
        description:
          'The hosted "change your password" page (#844): the current password and the new one. Replaced by the account console (#685). `Cache-Control: no-store`.',
        tags,
        'x-qauth-stability': 'experimental',
      },
      config,
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (session === null) {
        return startCeremony(request, reply, {
          intent: 'sign_in',
          returnTo: `${ACCOUNT_PAGE_PATH}/password`,
        });
      }
      const overview = await readAccountOverview(fastify, ceremonies.engines(), session);
      if (!overview.password.set) {
        return message(reply, 404, 'No password', 'Your account has no password to change.');
      }
      return sendPage(
        reply,
        passwordChangePage({
          cspNonce: reply.cspNonce.style,
          csrf: await accountCsrfToken(fastify, session),
          ...(overview.password.address === undefined
            ? {}
            : { address: overview.password.address }),
        })
      );
    }
  );

  app.post(
    '/account/password',
    {
      schema: {
        description:
          "Change the password with the current one (#844; the account API's `account.password.change`). Needs a sign-in from the last five minutes with the account's strongest factor. The new password meets the realm's password policy and breach list, or the page says why not; a wrong current password counts on the failure ladder. The account's other sessions and its refresh tokens end; this session stays.",
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [400, 403, 404, 429, 503],
        body: z.object({
          ...csrfBody,
          current_password: z.string().max(1024).default(''),
          new_password: z.string().max(1024).default(''),
        }),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(
        request,
        reply,
        request.body.csrf,
        ACCOUNT_PAGE_CHANGES.passwordChange,
        `${ACCOUNT_PAGE_PATH}/password`
      );
      if (session === null) return reply;
      const result = await changePassword(fastify, request, session, {
        current: request.body.current_password,
        next: request.body.new_password,
        mailer: ceremonies.engines().mailer,
      });
      const again = async (status: number, errors: readonly string[]) =>
        sendPage(
          reply,
          passwordChangePage({
            cspNonce: reply.cspNonce.style,
            csrf: await accountCsrfToken(fastify, session),
            errors,
          }),
          status
        );
      switch (result.kind) {
        case 'changed':
          return reply.redirect(overviewUrl(request, 'password_changed'), 303);
        case 'no_password':
          return message(reply, 404, 'No password', 'Your account has no password to change.');
        case 'wrong_password':
          return again(400, [CURRENT_PASSWORD_REFUSED]);
        case 'rejected':
          return again(400, result.messages);
        case 'wait':
          reply.header('Retry-After', String(result.retryAfterSeconds));
          return again(429, ['Too many wrong passwords. Wait a while, then try again.']);
        case 'unavailable':
          reply.header('Retry-After', '5');
          return again(503, ['Your password cannot be checked right now. Try again shortly.']);
      }
    }
  );

  app.post(
    '/account/reauthenticate',
    {
      schema: {
        description:
          'Confirm it’s you (#844): start a fresh sign-in on the hosted pages, which asks for the account’s strongest factor first, then come back to the account page.',
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403],
        body: z.object({
          ...csrfBody,
          return_to: z.enum(ACCOUNT_RETURN_PATHS).default(ACCOUNT_PAGE_PATH),
        }),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(request, reply, request.body.csrf);
      if (session === null) return reply;
      return startCeremony(request, reply, {
        intent: 'reauthenticate',
        returnTo: request.body.return_to,
        session: carried(session),
      });
    }
  );

  app.post(
    '/account/passkeys/add',
    {
      schema: {
        description:
          'Add a passkey (#844): a fresh sign-in on the hosted pages, then the passkey enrolment step of #651 on the realm origin, then back to the account page. Only while passkeys are on (`WEBAUTHN_ENABLED`).',
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403, 404],
        body: z.object(csrfBody),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(request, reply, request.body.csrf);
      if (session === null) return reply;
      if (fastify.passkeySignIn !== true) return notFound(reply);
      return startCeremony(request, reply, {
        intent: 'passkey',
        returnTo: ACCOUNT_PAGE_PATH,
        session: carried(session),
      });
    }
  );

  const passkeyParams = z.object({ passkeyId: z.uuid() });

  app.post(
    '/account/passkeys/:passkeyId/rename',
    {
      schema: {
        description:
          "Rename one of the account's passkeys (#844; `account.passkeys.update`). A name is no credential, so it needs no fresh sign-in; an empty name removes it.",
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403, 404],
        params: passkeyParams,
        body: z.object({ ...csrfBody, nickname: z.string().max(256).default('') }),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(
        request,
        reply,
        request.body.csrf,
        ACCOUNT_PAGE_CHANGES.passkeyRename
      );
      if (session === null) return reply;
      const result = await renamePasskey(fastify, request, session, {
        id: request.params.passkeyId,
        nickname: request.body.nickname,
      });
      if (result.kind === 'not_found') return notFound(reply);
      return reply.redirect(overviewUrl(request, 'passkey_renamed'), 303);
    }
  );

  /** The answer of a refused removal. */
  const refusedRemoval = (
    reply: FastifyReply,
    kind: 'last_credential' | 'second_factor_required'
  ) =>
    kind === 'last_credential'
      ? message(
          reply,
          409,
          'You need another way to sign in',
          'This is your last way to sign in. Add another one first, then remove this one.'
        )
      : message(
          reply,
          409,
          'You need another second factor',
          'Your account must keep a passkey or an authenticator app. Add another one first, then remove this one.'
        );

  app.post(
    '/account/passkeys/:passkeyId/remove',
    {
      schema: {
        description:
          "Remove one of the account's passkeys (#844; `account.passkeys.delete`). Needs a sign-in from the last five minutes with the account's strongest factor, or with a recovery code in place of a lost one; a passkey still new (bound after a sign-in that proved only the password, #1064) needs one with the password, and its removal ends the sessions whose sign-in bound or proved it, their codes and their refresh families, the account's recovery codes and every sign-in in progress. The account's last way to sign in, or the last second factor the realm requires, is refused (`409`).",
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403, 404, 409],
        params: passkeyParams,
        body: z.object(csrfBody),
      },
      config,
    },
    async (request, reply) => {
      // A passkey that is still new (#1064) the password alone removes.
      const session = await admitted(
        request,
        reply,
        request.body.csrf,
        ACCOUNT_PAGE_CHANGES.passkeyRemove,
        ACCOUNT_PAGE_PATH,
        { type: 'passkey', id: request.params.passkeyId }
      );
      if (session === null) return reply;
      const result = await removeCredential(
        fastify,
        request,
        session,
        { type: 'passkey', id: request.params.passkeyId },
        ceremonies.engines().mailer
      );
      if (result.kind === 'not_found') return notFound(reply);
      if (result.kind !== 'removed') return refusedRemoval(reply, result.kind);
      return reply.redirect(overviewUrl(request, 'passkey_removed'), 303);
    }
  );

  app.post(
    '/account/totp/setup',
    {
      schema: {
        description:
          'Set up an authenticator app (#844): a fresh sign-in on the hosted pages, then the TOTP set-up step of #653, then back to the account page. An account that has one is refused (`409`).',
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403, 409],
        body: z.object(csrfBody),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(request, reply, request.body.csrf);
      if (session === null) return reply;
      const overview = await readAccountOverview(fastify, ceremonies.engines(), session);
      if (overview.totp.set) {
        return message(
          reply,
          409,
          'Already set up',
          'Your account has an authenticator app. Turn it off first to set up another.'
        );
      }
      return startCeremony(request, reply, {
        intent: 'totp',
        returnTo: ACCOUNT_PAGE_PATH,
        session: carried(session),
      });
    }
  );

  app.post(
    '/account/totp/remove',
    {
      schema: {
        description:
          "Turn off the authenticator app (#844; `account.totp.delete`). Needs a sign-in from the last five minutes with the account's strongest factor, or with a recovery code in place of a lost one; an app still new (bound after a sign-in that proved only the password, #1064) needs one with the password, and turning it off ends the sessions whose sign-in bound or proved it, their codes and their refresh families, the account's recovery codes and every sign-in in progress. The last second factor the realm requires is refused (`409`).",
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403, 404, 409],
        body: z.object(csrfBody),
      },
      config,
    },
    async (request, reply) => {
      // An authenticator app that is still new (#1064) the password alone removes.
      const session = await admitted(
        request,
        reply,
        request.body.csrf,
        ACCOUNT_PAGE_CHANGES.totpRemove,
        ACCOUNT_PAGE_PATH,
        { type: 'totp' }
      );
      if (session === null) return reply;
      const result = await removeCredential(
        fastify,
        request,
        session,
        { type: 'totp' },
        ceremonies.engines().mailer
      );
      if (result.kind === 'not_found') return notFound(reply);
      if (result.kind !== 'removed') return refusedRemoval(reply, result.kind);
      return reply.redirect(overviewUrl(request, 'totp_removed'), 303);
    }
  );

  app.post(
    '/account/recovery-codes/regenerate',
    {
      schema: {
        description:
          "Issue a new set of recovery codes (#844; `account.recoveryCodes.regenerate`), shown once on the page this answers: every code of the old set stops working. Needs a sign-in from the last five minutes with the account's strongest factor. An account with no passkey and no authenticator app is refused (`409`). `Cache-Control: no-store`.",
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403, 409],
        body: z.object(csrfBody),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(
        request,
        reply,
        request.body.csrf,
        ACCOUNT_PAGE_CHANGES.recoveryCodesRegenerate
      );
      if (session === null) return reply;
      const result = await regenerateRecoveryCodes(fastify, request, ceremonies.engines(), session);
      if (result.kind === 'conflict') {
        return message(
          reply,
          409,
          'Add a second factor first',
          'Recovery codes stand in for a passkey or an authenticator app. Add one of them first.'
        );
      }
      return sendPage(
        reply,
        newRecoveryCodesPage({
          cspNonce: reply.cspNonce.style,
          csrf: await accountCsrfToken(fastify, session),
          codes: result.codes,
          setId: result.setId,
        })
      );
    }
  );

  app.post(
    '/account/recovery-codes/confirm',
    {
      schema: {
        description:
          'Say the new recovery codes are saved (#844). A set a newer one replaced meanwhile is not confirmed, and the page says so.',
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403],
        body: z.object({ ...csrfBody, set_id: z.string().max(64).default('') }),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(request, reply, request.body.csrf);
      if (session === null) return reply;
      const confirmed =
        request.body.set_id.length > 0 &&
        (await ceremonies.engines().recoveryCodes.confirm({
          realmId: session.realmId,
          userId: session.userId,
          setId: request.body.set_id,
        }));
      return reply.redirect(
        overviewUrl(request, confirmed ? 'recovery_codes_saved' : 'recovery_codes_replaced'),
        303
      );
    }
  );

  app.post(
    '/account/sessions/:sessionId/end',
    {
      schema: {
        description:
          "Sign one of the account's sessions out (#844; `account.sessions.delete`): its cookie stops working, and every app it signed in to with a back-channel logout URI is sent a logout token. A session of another account is `404`, untouched.",
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403, 404],
        params: z.object({ sessionId: z.uuid() }),
        body: z.object(csrfBody),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(
        request,
        reply,
        request.body.csrf,
        ACCOUNT_PAGE_CHANGES.sessionEnd
      );
      if (session === null) return reply;
      const sid = request.params.sessionId;
      const result = await endAccountSession(fastify, request, session, sid);
      if (result.kind === 'not_found') return notFound(reply);
      if (sid === session.sid) {
        clearSessionCookie(reply);
        return message(reply, 200, 'You’re signed out', 'This browser is signed out.', {
          href: ACCOUNT_PAGE_PATH,
          label: 'Sign in again',
        });
      }
      return reply.redirect(overviewUrl(request, 'session_ended'), 303);
    }
  );

  app.post(
    '/account/sessions/end-all',
    {
      schema: {
        description:
          'Sign out everywhere (#844; `account.sessions.endAll`): every session of the account ends, this one too, each app a session signed in to with a back-channel logout URI is sent a logout token, and every refresh token of the account is revoked.',
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403],
        body: z.object(csrfBody),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(
        request,
        reply,
        request.body.csrf,
        ACCOUNT_PAGE_CHANGES.sessionsEndAll
      );
      if (session === null) return reply;
      await endAllAccountSessions(fastify, request, session);
      clearSessionCookie(reply);
      return message(
        reply,
        200,
        'You’re signed out everywhere',
        'Every session of your account is signed out, and the apps you signed in to are told.',
        { href: ACCOUNT_PAGE_PATH, label: 'Sign in again' }
      );
    }
  );

  app.post(
    '/account/linked-accounts/link',
    {
      schema: {
        description:
          'Link an upstream account (#844, #670): the person signs in at the provider, then to this account again, with its own factors or through another provider whose identity the account already holds (#1080), in one interaction on the hosted pages; the identity the provider proved is linked then. Nothing is matched by an email address. Only a provider the realm offers and the account holds no identity of; any other is `404`.',
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403, 404],
        body: z.object({ ...csrfBody, provider: z.string().max(63).default('') }),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(request, reply, request.body.csrf);
      if (session === null) return reply;
      const overview = await readAccountOverview(fastify, ceremonies.engines(), session);
      const provider = overview.linkable.find((entry) => entry.provider === request.body.provider);
      if (provider === undefined) return notFound(reply);
      return startCeremony(request, reply, {
        intent: 'link',
        returnTo: ACCOUNT_PAGE_PATH,
        session: carried(session),
        provider: provider.provider,
      });
    }
  );

  app.post(
    '/account/linked-accounts/:linkedAccountId/unlink',
    {
      schema: {
        description:
          "Unlink one of the account's upstream accounts (#844; `account.linkedAccounts.delete`). Needs a sign-in from the last five minutes with the account's strongest factor. The account's last way to sign in is refused (`409`).",
        tags,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [403, 404, 409],
        params: z.object({ linkedAccountId: z.uuid() }),
        body: z.object(csrfBody),
      },
      config,
    },
    async (request, reply) => {
      const session = await admitted(
        request,
        reply,
        request.body.csrf,
        ACCOUNT_PAGE_CHANGES.linkedAccountRemove
      );
      if (session === null) return reply;
      const result = await unlinkUpstreamIdentity(fastify, request, {
        realm: requestRealm(request),
        userId: session.userId,
        credentialId: request.params.linkedAccountId,
        mailer: ceremonies.engines().mailer,
      });
      if (result.kind === 'not_found') return notFound(reply);
      if (result.kind === 'last_credential') return refusedRemoval(reply, 'last_credential');
      return reply.redirect(overviewUrl(request, 'unlinked'), 303);
    }
  );
}
