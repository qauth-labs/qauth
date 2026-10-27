import { defineKeys } from '../types';

/**
 * Service roles (ADR-019 Decision 8, issue #495): the keys of
 * `serviceRolesEnvSchema`. ADR-018 §5 puts the role switch in the stable
 * subset; the signer's address and the internal TLS files are advanced keys.
 */
export const SERVICE_ROLE_KEYS = defineKeys([
  {
    name: 'SERVICE_ROLES',
    tier: 'stable',
    role: 'deployment',
    owner: 'server',
    default: 'all',
    since: '0.2.0',
    docs: 'The roles this process runs, `all` or a comma-separated list of `web` (the browser-session endpoints), `api` (the token, discovery, account and developer endpoints), `admin`, `signer` (the KEK and every private key) and `delivery` (event delivery); each role registers only its own routes, plugins and jobs, and a process without `signer` refuses to boot when it finds a KEK or a private key variable.',
  },
  {
    name: 'SIGNER_URL',
    tier: 'advanced',
    role: 'deployment',
    owner: 'key-custody',
    default: null,
    since: '0.2.0',
    docs: 'The `https` URL of the signer service, required with the internal TLS files on a process whose `SERVICE_ROLES` leaves out `signer`; ignored, with a warning, where the signer runs in-process.',
  },
  {
    name: 'INTERNAL_TLS_CERT_PATH',
    tier: 'advanced',
    role: 'deployment',
    owner: 'server',
    default: null,
    since: '0.2.0',
    docs: "A PEM file with this process's certificate for internal traffic over mutual TLS, such as calls to the signer service; required where `SIGNER_URL` is.",
  },
  {
    name: 'INTERNAL_TLS_KEY_PATH',
    tier: 'advanced',
    role: 'deployment',
    owner: 'server',
    default: null,
    since: '0.2.0',
    docs: 'A PEM file with the private key of `INTERNAL_TLS_CERT_PATH`; required where `SIGNER_URL` is.',
  },
  {
    name: 'INTERNAL_TLS_CA_PATH',
    tier: 'advanced',
    role: 'deployment',
    owner: 'server',
    default: null,
    since: '0.2.0',
    docs: "A PEM file with the CA certificates that issue internal peers' certificates; required where `SIGNER_URL` is.",
  },
]);
