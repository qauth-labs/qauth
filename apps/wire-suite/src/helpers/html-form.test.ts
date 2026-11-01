import { describe, expect, it } from 'vitest';

import { decodeEntities, findForm, formBody, readForms } from './html-form';

const CONSENT_PAGE = `<!doctype html>
<html><body>
  <form class="card" method="post" action="/ui/consent">
    <h1>App wants to access your account</h1>
    <label class="forever">
      <input type="checkbox" name="allow_forever" value="1" checked />
      Remember this decision
    </label>
    <input type="hidden" name="csrf_token" value="tok-1" />
    <input type="hidden" name="state" value="a&amp;b=&quot;c&quot; &#39;d&#39;" />
    <input type="hidden" name="resource" value="https://rs.example/a" />
    <input type="hidden" name="resource" value="https://rs.example/b" />
    <input type="hidden" name="ignored" value="x" disabled />
    <input type="checkbox" name="unticked" value="1" />
    <div class="actions">
      <button type="submit" name="decision" value="deny" class="deny">Deny</button>
      <button type="submit" name="decision" value="allow" class="allow">Allow</button>
    </div>
  </form>
</body></html>`;

describe('reading an HTML form as a browser submits it', () => {
  it('decodes named and numeric character references', () => {
    expect(decodeEntities('&amp;&lt;&gt;&quot;&#39;&#x2F;&apos;&unknown;')).toBe(
      `&<>"'/'&unknown;`
    );
  });

  it('reads the method, the action, the submitted fields and the buttons', () => {
    const form = findForm(CONSENT_PAGE, '/ui/consent');

    expect(form).toEqual({
      method: 'POST',
      action: '/ui/consent',
      fields: [
        ['allow_forever', '1'],
        ['csrf_token', 'tok-1'],
        ['state', `a&b="c" 'd'`],
        ['resource', 'https://rs.example/a'],
        ['resource', 'https://rs.example/b'],
      ],
      buttons: [
        ['decision', 'deny'],
        ['decision', 'allow'],
      ],
    });
  });

  it('builds the body for a pressed button, with typed values replacing or joining the fields', () => {
    const form = findForm(CONSENT_PAGE, '/ui/consent');
    if (!form) throw new Error('no form');

    const body = formBody(form, { set: { allow_forever: null, extra: 'e' }, press: 'allow' });

    expect([...body]).toEqual([
      ['csrf_token', 'tok-1'],
      ['state', `a&b="c" 'd'`],
      ['resource', 'https://rs.example/a'],
      ['resource', 'https://rs.example/b'],
      ['extra', 'e'],
      ['decision', 'allow'],
    ]);
  });

  it('refuses a button the form does not have', () => {
    const form = findForm(CONSENT_PAGE, '/ui/consent');
    if (!form) throw new Error('no form');

    expect(() => formBody(form, { press: 'maybe' })).toThrow(/no button "maybe"/);
  });

  it('reads every form of a page, defaults the method to GET and finds none by a wrong action', () => {
    const page = `<form action="/a"><input name="q" value="1"></form><form method="POST" action='/b'></form>`;

    expect(readForms(page).map((form) => [form.method, form.action])).toEqual([
      ['GET', '/a'],
      ['POST', '/b'],
    ]);
    expect(readForms(page)[0].fields).toEqual([['q', '1']]);
    expect(findForm(page, '/c')).toBeUndefined();
  });
});
