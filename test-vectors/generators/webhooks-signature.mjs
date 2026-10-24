// Writes test-vectors/webhooks/signature.json with the Standard Webhooks
// reference library for JavaScript, at the version pinned below. Run by hand
// when a case is added; no test runs it, and the tests read the committed file.
//
//   npm pack standardwebhooks@1.1.1 && npm install --ignore-scripts ./standardwebhooks-1.1.1.tgz
//   node test-vectors/generators/webhooks-signature.mjs <that node_modules/standardwebhooks>
//
// The secrets are throwaway test secrets: each one is the base64 of a
// readable ASCII string that says so.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';

const PINNED = '1.1.1';
const OUT = 'test-vectors/webhooks/signature.json';

const packageDir = process.argv[2];
if (!packageDir)
  throw new Error('usage: webhooks-signature.mjs <path to the standardwebhooks package>');
const pkg = JSON.parse(readFileSync(join(packageDir, 'package.json'), 'utf8'));
if (pkg.name !== 'standardwebhooks' || pkg.version !== PINNED) {
  throw new Error(`expected standardwebhooks@${PINNED}, found ${pkg.name}@${pkg.version}`);
}
const { Webhook } = createRequire(import.meta.url)(resolve(packageDir));

const secret = (text) => `whsec_${Buffer.from(text, 'ascii').toString('base64')}`;
const THROWAWAY = secret('qauth throwaway test #01');
const EVENT = {
  id: '0199f2b4-7c3e-7a51-9d2b-3a6c8e1f0a42',
  type: 'urn:qauth:event:user.signed_in:v1-rc.0',
  time: '2026-10-22T09:30:00.123Z',
  realm: '0199f2b4-1a2b-7c3d-8e4f-5a6b7c8d9e0f',
  category: 'user',
  actor: { type: 'user', id: '0199f2b4-2b3c-7d4e-9f5a-6b7c8d9e0f1a' },
  subject: { type: 'user', id: '0199f2b4-2b3c-7d4e-9f5a-6b7c8d9e0f1a' },
  data: { method: 'password' },
};

const cases = [
  {
    id: 'reference-library-example',
    input: {
      secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
      id: 'msg_p5jXN8AQM9LWM0D4loKWxJek',
      timestamp: 1614265330,
      body: '{"test": 2432232314}',
    },
    notes:
      "The secret, id, timestamp and body of the reference libraries' own tests. The secret is public and secures nothing.",
  },
  {
    id: 'qauth-event',
    input: { secret: THROWAWAY, id: EVENT.id, timestamp: 1792661400, body: JSON.stringify(EVENT) },
    notes: 'A QAuth event as a webhook body: the webhook-id is the event id.',
  },
  {
    id: 'body-signed-byte-for-byte',
    input: {
      secret: THROWAWAY,
      id: EVENT.id,
      timestamp: 1792661400,
      body: `${JSON.stringify(EVENT, null, 2)}\n`,
    },
    notes:
      'The same event, pretty-printed with a trailing newline. The signature covers the body as sent, never a re-serialized form, so it differs from qauth-event.',
  },
  {
    id: 'non-ascii-body',
    input: { secret: THROWAWAY, id: 'msg_utf8', timestamp: 1792661400, body: '{"name":"Zoë 🔐"}' },
    notes: 'The body is signed as UTF-8 bytes.',
  },
  {
    id: 'empty-body',
    input: { secret: THROWAWAY, id: 'msg_empty', timestamp: 1792661400, body: '' },
    notes: 'The signed content still has both full stops: "msg_empty.1792661400.".',
  },
  {
    id: 'other-secret',
    input: {
      secret: secret('qauth throwaway test #02'),
      id: EVENT.id,
      timestamp: 1792661400,
      body: JSON.stringify(EVENT),
    },
    notes: 'qauth-event under another secret: the signature depends on the key.',
  },
];

const file = {
  schema: 'qauth-vectors/1-rc.0',
  id: 'webhooks/signature',
  description:
    'Standard Webhooks signatures. input.secret is the signing secret in its whsec_ form: the bytes after the prefix, base64-decoded, are the HMAC key. input.id, input.timestamp (Unix seconds) and input.body (text, signed as its UTF-8 bytes) are the webhook-id, webhook-timestamp and body of one message. expected.signature is the webhook-signature header value, "v1," followed by the standard base64 of HMAC-SHA256(key, id + "." + timestamp + "." + body). Every secret except the one in reference-library-example is a throwaway test secret: it decodes to an ASCII string that says so.',
  source: `Standard Webhooks specification, "Signature scheme"; generated with the reference JavaScript library standardwebhooks@${PINNED} (npm) by test-vectors/generators/webhooks-signature.mjs`,
  cases: cases.map(({ id, input, notes }) => ({
    id,
    input,
    expected: {
      signature: new Webhook(input.secret).sign(
        input.id,
        new Date(input.timestamp * 1000),
        input.body
      ),
    },
    notes,
  })),
};

writeFileSync(OUT, `${JSON.stringify(file, null, 2)}\n`);
execFileSync('pnpm', ['exec', 'prettier', '--write', '--log-level', 'warn', OUT], {
  stdio: 'inherit',
});
console.log(`wrote ${OUT} (${file.cases.length} cases)`);
