import { defineKeys } from '../types';

/**
 * The internal listener (ADR-019 Decision 8, issue #496): the keys of
 * `internalListenerEnvSchema`. Advanced keys: the distributed deployment they
 * wire is outside ADR-018 §5's documented subset. Its TLS files are the
 * service roles' (`service-roles.ts`).
 */
export const INTERNAL_LISTENER_KEYS = defineKeys([
  {
    name: 'INTERNAL_HOST',
    tier: 'advanced',
    role: 'deployment',
    owner: 'server',
    default: '127.0.0.1',
    since: '0.2.0',
    docs: "The address the internal listener binds to, loopback by default; the listener runs only on a process whose `SERVICE_ROLES` holds `signer` but not every role, for the other roles' calls to the signer service, and serves mutual TLS only, while a single process runs none.",
  },
  {
    name: 'INTERNAL_PORT',
    tier: 'advanced',
    role: 'deployment',
    owner: 'server',
    default: '3443',
    since: '0.2.0',
    docs: "The TCP port the internal listener binds to; it must differ from `PORT` and from `ADMIN_API_PORT` where the admin API's listener runs.",
  },
  {
    name: 'INTERNAL_PEER_ROLES',
    tier: 'advanced',
    role: 'deployment',
    owner: 'server',
    default: null,
    since: '0.2.0',
    docs: 'A JSON object from a subject alternative name of a peer\'s certificate, a URI such as a SPIFFE ID or a DNS name, to the service role the peer calls the internal listener as, such as `{"spiffe://example.org/qauth/web":"web"}`; the listener answers `403` to a peer whose certificate names no SAN here, and to one whose role a route\'s module does not admit; `signer` is refused, as the signer never calls as a peer, and with the internal TLS files the listener refuses to start without one.',
  },
]);
