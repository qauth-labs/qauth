import { describe, expect, expectTypeOf, it, vi } from 'vitest';

import {
  type AnswerRequest,
  createInteractionClient,
  type Interaction,
  type NewPasswordParams,
  type Problem,
  type StepName,
} from '../index';
import { expandPath, UnexpectedRedirectError, UnexpectedStatusError } from './runtime';

const ID = 'aW50ZXJhY3Rpb24taWQtb2YtMzItcmFuZG9tLWJ5dGU';
const CSRF = 'cGVyLXN0ZXAtY3NyZi12YWx1ZS1vZi0zMi1ieXRlcyE';

function jsonResponse(status: number, body: unknown, contentType = 'application/json') {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': contentType } });
}

describe('the Interaction API client', () => {
  it('reads the current step on the configured origin, with no body', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => jsonResponse(200, { step: {} }));
    const client = createInteractionClient({ baseUrl: 'https://auth.example.com', fetch });
    const result = await client.interactionsGet({ interactionId: ID });
    expect(result.status).toBe(200);
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe(`https://auth.example.com/interaction/v1-rc.0/${ID}`);
    expect(init).toMatchObject({ method: 'GET', credentials: 'same-origin', redirect: 'manual' });
    expect(init?.body).toBeUndefined();
  });

  it('posts an answer as JSON, same-origin, without following a redirect', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      jsonResponse(200, { result: 'redirect', location: 'https://app.example.com/cb' })
    );
    const client = createInteractionClient({ fetch });
    const answer: AnswerRequest = {
      type: 'urn:qauth:ia:password:v1-rc.0',
      csrf: CSRF,
      password: 'correct horse battery staple x',
    };
    const result = await client.interactionsAnswer({ interactionId: ID }, answer);
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe(`/interaction/v1-rc.0/${ID}/answer`);
    expect(init?.method).toBe('POST');
    expect(init?.credentials).toBe('same-origin');
    expect(init?.redirect).toBe('manual');
    expect(init?.headers).toMatchObject({ 'content-type': 'application/json' });
    expect(JSON.parse(String(init?.body))).toEqual(answer);
    if (result.status === 200) {
      expectTypeOf(result.data).toEqualTypeOf<
        { result: 'step'; interaction: Interaction } | { result: 'redirect'; location: string }
      >();
    }
    expect(result.data).toEqual({ result: 'redirect', location: 'https://app.example.com/cb' });
  });

  it('reads a problem document as data, typed by its status', async () => {
    const problem = {
      type: 'https://docs.qauth.dev/reference/problem-types/#interaction-expired',
      title: 'Interaction expired',
      status: 410,
      code: 'interaction_expired',
      trace_id: 'req-1',
    };
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      jsonResponse(410, problem, 'application/problem+json')
    );
    const result = await createInteractionClient({ fetch }).interactionsPersonalGet({
      interactionId: ID,
    });
    expect(result).toMatchObject({ status: 410, data: problem });
    if (result.status === 410) expectTypeOf(result.data).toEqualTypeOf<Problem>();
  });

  it('refuses a status the document does not declare, such as a proxy’s 502', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(
      async () =>
        new Response('<html></html>', { status: 502, headers: { 'content-type': 'text/html' } })
    );
    const call = createInteractionClient({ fetch }).interactionsGet({ interactionId: ID });
    await expect(call).rejects.toBeInstanceOf(UnexpectedStatusError);
    await expect(call).rejects.toMatchObject({ status: 502 });
  });

  // A browser's `fetch` with `redirect: 'manual'` hides a redirect: an
  // `opaqueredirect` response with status 0.
  it('refuses a redirect a browser hid from it, by name rather than as status 0', async () => {
    const opaque = new Response(null, { status: 200 });
    Object.defineProperty(opaque, 'type', { value: 'opaqueredirect' });
    Object.defineProperty(opaque, 'status', { value: 0 });
    const fetch = vi.fn<typeof globalThis.fetch>(async () => opaque);
    const call = createInteractionClient({ fetch }).interactionsAnswer(
      { interactionId: ID },
      { type: 'urn:qauth:ia:password:v1-rc.0', csrf: CSRF, password: 'x' }
    );
    await expect(call).rejects.toBeInstanceOf(UnexpectedRedirectError);
    await expect(call).rejects.toBeInstanceOf(UnexpectedStatusError);
    await expect(call).rejects.toThrow(/answered with a redirect/);
  });

  it('reads no body from a declared answer that is not JSON', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response(null, { status: 303 }));
    const result = await createInteractionClient({ fetch }).interactionsCancel(
      { interactionId: ID },
      { csrf: CSRF }
    );
    expect(result.status).toBe(303);
    expect(result.data).toBeUndefined();
  });

  it('refuses an interaction id that does not have the id’s shape', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => jsonResponse(200, {}));
    const client = createInteractionClient({ fetch });
    for (const interactionId of ['..', '../answer', '', `${ID}/../x`, 'a'.repeat(42)]) {
      await expect(
        client.interactionsAnswer({ interactionId }, { csrf: CSRF } as never),
        interactionId
      ).rejects.toBeInstanceOf(TypeError);
    }
    expect(fetch).not.toHaveBeenCalled();
    expect(expandPath('/i/{id}', { id: 'a_b-c' }, { id: '^[a-z_-]+$' })).toBe('/i/a_b-c');
    expect(() => expandPath('/i/{id}', { id: 'x' }, {})).toThrow(TypeError);
  });

  it('types each offered step’s params by its name', () => {
    const read = (interaction: Interaction) => {
      expectTypeOf(interaction.step).toEqualTypeOf<StepName>();
      const params = interaction.params['urn:qauth:ia:new_password:v1-rc.0'];
      expectTypeOf(params).toEqualTypeOf<NewPasswordParams | undefined>();
      if (params !== undefined) {
        expectTypeOf(params.purpose).toEqualTypeOf<'register' | 'reset' | 'update_required'>();
      }
      const captcha = interaction.params['urn:qauth:ia:captcha:v1-rc.0'];
      if (captcha?.provider === 'pow') expectTypeOf(captcha.difficulty).toEqualTypeOf<number>();
    };
    expect(read).toBeTypeOf('function');
  });
});
