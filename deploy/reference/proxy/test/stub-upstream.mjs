// A stub upstream for the reference proxy test (#482). It stands in for the
// auth server or the ceremony app: it answers every request with what it
// received (method, request target, headers) as JSON, and logs one JSON line
// per request so the test can prove a request never reached it.
//
// Environment:
//   STUB_NAME  the upstream it plays, echoed in `X-Stub-Upstream` and the body
//   STUB_WEAK  "1" to send a weak Content-Security-Policy, a public
//              Cache-Control and a leaky Referrer-Policy on every answer, as a
//              careless ceremony app would; the proxy must replace all three
//
// Request headers that shape the answer (they pass through the proxy):
//   X-Stub-Status      the status code to answer with (default 200)
//   X-Stub-Set-Cookie  a Set-Cookie value to send
//   X-Stub-Hang-Up     close the connection without an answer, so the proxy
//                      has to answer by itself (502)
//
// Plain Node, no dependencies: it runs in a stock node image.
import { createServer } from 'node:http';

const name = process.env.STUB_NAME ?? 'stub';
const weak = process.env.STUB_WEAK === '1';
const port = Number(process.env.PORT ?? '3000');

const server = createServer((request, response) => {
  const marker = request.headers['x-test-marker'] ?? null;
  console.log(JSON.stringify({ stub: name, marker, method: request.method, url: request.url }));

  if (request.headers['x-stub-hang-up'] !== undefined) {
    request.socket.destroy();
    return;
  }

  // Drain the body; the echo does not need it.
  request.resume();
  request.on('end', () => {
    const status = Number(request.headers['x-stub-status'] ?? '200');
    const headers = {
      'content-type': 'application/json',
      'x-stub-upstream': name,
    };
    if (weak) {
      headers['content-security-policy'] = "script-src * 'unsafe-inline' 'unsafe-eval'";
      headers['cache-control'] = 'public, max-age=3600';
      headers['referrer-policy'] = 'unsafe-url';
    }
    const setCookie = request.headers['x-stub-set-cookie'];
    if (typeof setCookie === 'string') headers['set-cookie'] = setCookie;

    const body = JSON.stringify({
      upstream: name,
      method: request.method,
      url: request.url,
      headers: request.headers,
    });
    response.writeHead(status, headers);
    response.end(request.method === 'HEAD' ? undefined : body);
  });
});

server.listen(port, '0.0.0.0', () => {
  console.log(JSON.stringify({ stub: name, listening: port }));
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
