import { type AddressInfo, connect, createServer, type Socket } from 'node:net';

/**
 * TEST SUPPORT — a TCP relay in front of a dependency (#500), so a suite can
 * take the dependency away from one server while the shared container keeps
 * serving every other suite: point the server's DATABASE_URL or REDIS_URL at
 * the relay, then {@link TcpRelay.stop} it. Every connection through it is
 * cut and no new one is accepted, as when the dependency stops.
 */
export interface TcpRelay {
  /** The loopback port the relay listens on. */
  readonly port: number;
  /** Rewrite `url`'s host and port to the relay's. */
  through(url: string): string;
  /** Cut every connection and stop listening; idempotent. */
  stop(): Promise<void>;
}

/** Relay loopback connections to `target`. */
export async function startTcpRelay(target: {
  readonly host: string;
  readonly port: number;
}): Promise<TcpRelay> {
  const sockets = new Set<Socket>();
  const server = createServer((client) => {
    const upstream = connect(target.port, target.host);
    sockets.add(client);
    sockets.add(upstream);
    const cut = () => {
      client.destroy();
      upstream.destroy();
      sockets.delete(client);
      sockets.delete(upstream);
    };
    for (const socket of [client, upstream]) {
      socket.on('error', cut);
      socket.on('close', cut);
    }
    client.pipe(upstream);
    upstream.pipe(client);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const { port } = server.address() as AddressInfo;
  let stopped: Promise<void> | undefined;

  return {
    port,
    through(url: string): string {
      const parsed = new URL(url);
      parsed.hostname = '127.0.0.1';
      parsed.port = String(port);
      return parsed.toString();
    },
    stop(): Promise<void> {
      stopped ??= new Promise<void>((resolve) => {
        server.close(() => resolve());
        for (const socket of sockets) socket.destroy();
        sockets.clear();
      });
      return stopped;
    },
  };
}
