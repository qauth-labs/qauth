/**
 * TEST SUPPORT — the environment a split process holding the signer boots
 * with (#496): such a process serves the signer to the other roles on the
 * internal listener, over mutual TLS only, and refuses to boot without the
 * internal TLS files and INTERNAL_PEER_ROLES.
 *
 * The paths are never read by a boot that runs no internal listener, as
 * `bootAuthServer` without its `internalListener` option does: spread this
 * into such a boot's environment.
 */
export const SIGNER_LISTENER: Readonly<Record<string, string>> = Object.freeze({
  INTERNAL_TLS_CERT_PATH: '/run/secrets/signer.crt',
  INTERNAL_TLS_KEY_PATH: '/run/secrets/signer.key',
  INTERNAL_TLS_CA_PATH: '/run/secrets/internal-ca.crt',
  INTERNAL_PEER_ROLES: JSON.stringify({ 'spiffe://qauth.test/web': 'web' }),
});
