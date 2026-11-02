/**
 * TEST SUPPORT — the environments of split processes (#495, #496, #500).
 *
 * Every split process runs the internal listener while METRICS_ENABLED is on,
 * to serve its metrics to a scraper (#500), so each environment maps a
 * scraper's SAN to the `metrics` peer role. A process holding the signer
 * serves the signer to the other roles there too, over mutual TLS only, and
 * refuses to boot without the internal TLS files and INTERNAL_PEER_ROLES.
 *
 * The paths are never read by a boot that runs no internal listener, as
 * `bootAuthServer` without its `internalListener` option does: spread these
 * into such a boot's environment.
 */

/** INTERNAL_PEER_ROLES' entry of a metrics scraper (#500). */
export const METRICS_PEER: Readonly<Record<string, string>> = Object.freeze({
  'spiffe://qauth.test/prometheus': 'metrics',
});

/** A split process holding the signer: its internal listener's mutual TLS. */
export const SIGNER_LISTENER: Readonly<Record<string, string>> = Object.freeze({
  INTERNAL_TLS_CERT_PATH: '/run/secrets/signer.crt',
  INTERNAL_TLS_KEY_PATH: '/run/secrets/signer.key',
  INTERNAL_TLS_CA_PATH: '/run/secrets/internal-ca.crt',
  INTERNAL_PEER_ROLES: JSON.stringify({ 'spiffe://qauth.test/web': 'web', ...METRICS_PEER }),
});

/**
 * A split process without the signer: where it reaches the signer service
 * (never dialled), over the mutual TLS its internal listener serves the
 * metrics with.
 */
export const SIGNER_SERVICE: Readonly<Record<string, string>> = Object.freeze({
  SIGNER_URL: 'https://signer.internal:3443',
  INTERNAL_TLS_CERT_PATH: '/run/secrets/internal.crt',
  INTERNAL_TLS_KEY_PATH: '/run/secrets/internal.key',
  INTERNAL_TLS_CA_PATH: '/run/secrets/internal-ca.crt',
  INTERNAL_PEER_ROLES: JSON.stringify(METRICS_PEER),
});
