import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * A throwaway HTTP server on a loopback port, for the helpers' own unit tests.
 * Never used by a wire test: those talk to the server under test.
 */
export interface LoopbackServer {
  readonly url: string;
  close(): Promise<void>;
}

export async function startLoopbackServer(
  handler: (request: IncomingMessage, response: ServerResponse, body: string) => void
): Promise<LoopbackServer> {
  const server = createServer((request, response) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk: string) => (body += chunk));
    request.on('end', () => handler(request, response, body));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
