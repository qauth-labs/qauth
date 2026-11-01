import { createServer, type Socket } from 'node:net';

/**
 * TEST SUPPORT — a local SMTP server that records what it receives (#529).
 *
 * Just enough of RFC 5321 for nodemailer: `EHLO`/`HELO`, `AUTH PLAIN` (RFC
 * 4616), `MAIL`, `RCPT`, `DATA`, `RSET`, `NOOP` and `QUIT`, on loopback, with
 * no TLS, so a realm's `smtp` transport with `secure: false` sends to it.
 * Each sign-in and each message is recorded, so a suite can tell which of two
 * fixtures a realm's mail reached and with which password.
 */

/** One `AUTH PLAIN` sign-in. */
export interface SmtpLogin {
  readonly user: string;
  readonly password: string;
  /** Whether the fixture accepted it. */
  readonly accepted: boolean;
}

/** One message the fixture accepted. */
export interface SmtpMessage {
  /** The `MAIL FROM` address. */
  readonly from: string;
  /** The `RCPT TO` addresses. */
  readonly to: readonly string[];
  /** The message as sent after `DATA`, headers and body, with CRLF line ends. */
  readonly data: string;
  /** The user the session signed in as, if it did. */
  readonly user?: string;
}

/** A running fixture. */
export interface SmtpFixture {
  readonly host: string;
  readonly port: number;
  readonly logins: SmtpLogin[];
  readonly messages: SmtpMessage[];
  /** Resolve once `count` messages arrived, or reject after `timeoutMs`. */
  waitForMessages(count: number, timeoutMs?: number): Promise<readonly SmtpMessage[]>;
  close(): Promise<void>;
}

/** What {@link startSmtpFixture} takes. */
export interface SmtpFixtureOptions {
  /** The only password the fixture accepts; any password when unset. */
  readonly password?: string;
}

/** The address inside `MAIL FROM:<a@b>` or `RCPT TO:<a@b>`. */
function addressOf(argument: string): string {
  const match = /<([^>]*)>/.exec(argument);
  return match?.[1] ?? argument.trim();
}

/** Start a fixture on a free loopback port. */
export async function startSmtpFixture(options: SmtpFixtureOptions = {}): Promise<SmtpFixture> {
  const logins: SmtpLogin[] = [];
  const messages: SmtpMessage[] = [];
  const sockets = new Set<Socket>();
  const waiters = new Set<() => void>();

  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
    socket.setEncoding('utf8');

    let buffered = '';
    let inData = false;
    let dataLines: string[] = [];
    let from = '';
    let to: string[] = [];
    let user: string | undefined;
    let awaitingPlain = false;
    const reply = (line: string) => socket.write(`${line}\r\n`);

    const signIn = (encoded: string) => {
      const [, name = '', password = ''] = Buffer.from(encoded.trim(), 'base64')
        .toString('utf8')
        .split('\u0000');
      const accepted = options.password === undefined || password === options.password;
      logins.push({ user: name, password, accepted });
      if (accepted) {
        user = name;
        reply('235 2.7.0 Authentication successful');
      } else {
        reply('535 5.7.8 Authentication credentials invalid');
      }
    };

    const handle = (line: string) => {
      if (inData) {
        if (line === '.') {
          inData = false;
          messages.push({
            from,
            to,
            data: dataLines
              .map((text) => (text.startsWith('..') ? text.slice(1) : text))
              .join('\r\n'),
            ...(user === undefined ? {} : { user }),
          });
          dataLines = [];
          for (const wake of waiters) wake();
          reply('250 2.0.0 OK queued');
        } else {
          dataLines.push(line);
        }
        return;
      }
      if (awaitingPlain) {
        awaitingPlain = false;
        signIn(line);
        return;
      }
      const [verb = '', ...rest] = line.split(' ');
      const argument = rest.join(' ');
      switch (verb.toUpperCase()) {
        case 'EHLO':
          socket.write('250-fixture.local\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n');
          return;
        case 'HELO':
          return reply('250 fixture.local');
        case 'AUTH': {
          const [mechanism = '', initial] = argument.split(' ');
          if (mechanism.toUpperCase() !== 'PLAIN') return reply('504 5.5.4 Unrecognized mechanism');
          if (initial === undefined) {
            awaitingPlain = true;
            return reply('334 ');
          }
          return signIn(initial);
        }
        case 'MAIL':
          from = addressOf(argument);
          to = [];
          return reply('250 2.1.0 OK');
        case 'RCPT':
          to.push(addressOf(argument));
          return reply('250 2.1.5 OK');
        case 'DATA':
          inData = true;
          return reply('354 End data with <CR><LF>.<CR><LF>');
        case 'RSET':
          from = '';
          to = [];
          return reply('250 2.0.0 OK');
        case 'NOOP':
          return reply('250 2.0.0 OK');
        case 'QUIT':
          reply('221 2.0.0 Bye');
          socket.end();
          return;
        default:
          return reply('502 5.5.2 Command not implemented');
      }
    };

    socket.on('data', (chunk: string) => {
      buffered += chunk;
      let end = buffered.indexOf('\r\n');
      while (end !== -1) {
        handle(buffered.slice(0, end));
        buffered = buffered.slice(end + 2);
        end = buffered.indexOf('\r\n');
      }
    });
    reply('220 fixture.local ESMTP');
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no fixture port');

  return {
    host: '127.0.0.1',
    port: address.port,
    logins,
    messages,
    waitForMessages(count, timeoutMs = 10_000) {
      return new Promise((resolve, reject) => {
        if (messages.length >= count) return resolve([...messages]);
        const timer = setTimeout(() => {
          waiters.delete(check);
          reject(new Error(`the SMTP fixture got ${messages.length} of ${count} messages`));
        }, timeoutMs);
        const check = () => {
          if (messages.length < count) return;
          clearTimeout(timer);
          waiters.delete(check);
          resolve([...messages]);
        };
        waiters.add(check);
      });
    },
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
