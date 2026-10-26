import { createRequire } from 'node:module';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  type E2eInfrastructure,
  extractCsrfToken,
  generateJwtPem,
  type PemKeyPair,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE VERIFICATION MAIL'S LINK VERIFIES THE ACCOUNT, IN A BROWSER, ON THE
 * DEFAULTS.
 *
 * Since 42c4d1e4 the auth server verified only on `POST /auth/verify`, while
 * the mail links to `<EMAIL_BASE_URL>/auth/verify?token=…`, which a mail
 * client opens with GET: a 404. With `REQUIRE_VERIFIED_ACCOUNT` on by default,
 * a new password account could then never sign in.
 *
 * Against a real Postgres and Redis: register, take the link out of the mail
 * the mock provider was handed, open it as a browser does, submit the page's
 * form, and sign in. Opening the link alone (a link scanner, a prefetch)
 * changes nothing.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const EMAIL = 'new-user@example.test';
const PASSWORD = 'Copper-Kettle-Morning-58!';

/** One mail as the mock provider received it. */
interface SentMail {
  readonly to: string;
  readonly subject: string;
  readonly text?: string;
  readonly html?: string;
}

/** What the suite reads of `@qauth-labs/server-email`. */
interface EmailLibrary {
  readonly MockEmailProvider: { prototype: { sendEmail(options: SentMail): Promise<unknown> } };
}

/**
 * Import the email library the email plugin uses. It is a dependency of
 * `@qauth-labs/fastify-plugin-email`, not of the auth server, so it is
 * resolved from the plugin's package. Called after `bootAuthServer`, which
 * reset the module registry and imported the app, so the module is the
 * instance the app loaded and a spy on its provider sees the app's mail.
 */
async function loadEmailLibrary(): Promise<EmailLibrary> {
  const plugin = createRequire(__filename).resolve('@qauth-labs/fastify-plugin-email/package.json');
  const library = createRequire(plugin).resolve('@qauth-labs/server-email');
  return (await import(library)) as EmailLibrary;
}

describe('the verification link of the mail (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  /**
   * A deployment on the defaults, with the mock mail provider's sends spied
   * on. The spy is set on the provider class the app loaded: `bootAuthServer`
   * reset the module registry and imported the app, so importing the email
   * library now yields that same instance.
   */
  async function withDeployment<T>(
    body: (app: FastifyInstance, mails: MockInstance) => Promise<T>
  ): Promise<T> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    let booted: BootedAuthServer | undefined;
    let mails: MockInstance | undefined;
    try {
      booted = await bootAuthServer({
        ...baseEnvironment(infra, jwt),
        // Blank is unset (as docker-compose.yml forwards it): the DEFAULT gate.
        REQUIRE_VERIFIED_ACCOUNT: '',
        REQUIRE_EMAIL_VERIFIED: '',
      });
      await resetE2eState(booted.app);
      const { MockEmailProvider } = await loadEmailLibrary();
      mails = vi.spyOn(MockEmailProvider.prototype, 'sendEmail');
      return await body(booted.app, mails);
    } finally {
      mails?.mockRestore();
      await booted?.close();
    }
  }

  /** The verification link of the last mail sent to `to`. */
  async function mailedLink(mails: MockInstance, to: string): Promise<URL> {
    await vi.waitFor(() =>
      expect(mails).toHaveBeenCalledWith(
        expect.objectContaining({ to, subject: 'Verify your email address' })
      )
    );
    const mail = mails.mock.calls
      .map(([options]) => options as SentMail)
      .filter((options) => options.to === to)
      .at(-1);
    const found = /https?:\/\/[^\s"<>]+\/auth\/verify\?token=[0-9a-f]{64}/.exec(mail?.text ?? '');
    if (found === null) throw new Error('no verification link in the mail');
    // The HTML part's button carries the same link.
    expect(mail?.html).toContain(found[0]);
    return new URL(found[0]);
  }

  /** Open the link in a browser: GET it, keeping what the page sets. */
  async function openLink(app: FastifyInstance, link: URL, jar: CookieJar) {
    const page = await app.inject({ method: 'GET', url: `${link.pathname}${link.search}` });
    jar.absorb(page.headers['set-cookie']);
    return page;
  }

  /** Submit the page's form with `password`, as the browser posts it. */
  function submitForm(
    app: FastifyInstance,
    page: LightMyRequestResponse,
    jar: CookieJar,
    password: string
  ) {
    const token = /name="token" value="([0-9a-fA-F]{64})"/.exec(page.body)?.[1];
    if (token === undefined) throw new Error('no token field in the page');
    return app.inject({
      method: 'POST',
      url: '/ui/verify',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        ...(jar.header() === undefined ? {} : { cookie: jar.header() }),
      },
      payload: new URLSearchParams({
        token,
        password,
        csrf_token: extractCsrfToken(page.body),
      }).toString(),
    });
  }

  function login(app: FastifyInstance, password = PASSWORD) {
    return app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: EMAIL, password },
    });
  }

  it('registers, opens the mailed link, confirms with the password, and signs in', async () => {
    await withDeployment(async (app, mails) => {
      expect(
        (
          await app.inject({
            method: 'POST',
            url: '/auth/register',
            payload: { email: EMAIL, password: PASSWORD },
          })
        ).statusCode
      ).toBe(202);
      const link = await mailedLink(mails, EMAIL);

      // The link points at the auth server: the issuer's origin, /auth/verify.
      expect(link.origin).toBe('https://auth.example.com');
      expect(link.pathname).toBe('/auth/verify');

      // Not verified yet: the default gate refuses the sign-in.
      expect((await login(app)).statusCode).toBe(401);

      // A link scanner fetches the link first, twice, with GET and HEAD.
      // Nothing changes: the account still cannot sign in.
      const scanner = new CookieJar();
      expect((await openLink(app, link, scanner)).statusCode).toBe(200);
      expect(
        (await app.inject({ method: 'HEAD', url: `${link.pathname}${link.search}` })).statusCode
      ).toBe(200);
      expect((await login(app)).statusCode).toBe(401);

      // The person opens it: a page, not a 404, with no-store and no-referrer.
      const jar = new CookieJar();
      const page = await openLink(app, link, jar);
      expect(page.statusCode).toBe(200);
      expect(page.headers['content-type']).toBe('text/html; charset=utf-8');
      expect(page.headers['cache-control']).toBe('no-store');
      expect(page.headers['referrer-policy']).toBe('no-referrer');
      expect(page.body).toContain('<form method="post" action="/ui/verify">');

      // A wrong password keeps the form and consumes nothing.
      const wrong = await submitForm(app, page, jar, 'Not-The-Password-12!');
      expect(wrong.statusCode).toBe(401);
      expect(wrong.body).toContain('That password does not match this account.');

      // The right one verifies.
      const done = await submitForm(app, wrong, jar, PASSWORD);
      expect(done.statusCode).toBe(200);
      expect(done.body).toContain('Email address verified');
      expect(done.body).toContain(EMAIL);

      // And the account signs in, through the API and the hosted login page.
      const signedIn = await login(app);
      expect(signedIn.statusCode).toBe(200);
      expect(signedIn.json()).toMatchObject({ access_token: expect.any(String) });

      const loginJar = new CookieJar();
      const loginPage = await app.inject({ method: 'GET', url: '/ui/login' });
      loginJar.absorb(loginPage.headers['set-cookie']);
      const uiLogin = await app.inject({
        method: 'POST',
        url: '/ui/login',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          cookie: loginJar.header() as string,
        },
        payload: new URLSearchParams({
          email: EMAIL,
          password: PASSWORD,
          csrf_token: extractCsrfToken(loginPage.body),
        }).toString(),
      });
      expect(uiLogin.statusCode).toBe(302);

      // The token is spent: the form and the JSON API both answer 400.
      const again = await openLink(app, link, jar);
      expect(again.statusCode).toBe(200);
      const reused = await submitForm(app, again, jar, PASSWORD);
      expect(reused.statusCode).toBe(400);
      expect(reused.body).toContain('This link is no longer valid');
      const reusedJson = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: { token: link.searchParams.get('token'), password: PASSWORD },
      });
      expect(reusedJson.statusCode).toBe(reused.statusCode);
    });
  }, 120_000);

  it('refuses a form post without the page’s CSRF cookie, and verifies nothing', async () => {
    await withDeployment(async (app, mails) => {
      await app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: { email: EMAIL, password: PASSWORD },
      });
      const link = await mailedLink(mails, EMAIL);
      const page = await openLink(app, link, new CookieJar());

      // A cross-site post carries no __Host- cookie of this origin.
      const forged = await submitForm(app, page, new CookieJar(), PASSWORD);

      expect(forged.statusCode).toBe(403);
      expect((await login(app)).statusCode).toBe(401);
    });
  }, 120_000);
});
