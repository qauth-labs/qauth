/**
 * The QAuth release this server was built from (#499): what the OpenAPI
 * document's `info.version` says, and what the node list compares, since only
 * nodes of the same release must hold the same deployment-wide settings.
 */

/** The version of every build that is not a release. */
export const UNRELEASED_VERSION = '0.0.0-dev';

/** A release version as `release-images.yml` reads it from the tag: `X.Y.Z` or `X.Y.Z-rc.N`. */
const RELEASE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-rc\.(0|[1-9]\d*))?$/;

/**
 * The release the server was built from. The release workflow passes the
 * tag's version into the image as `QAUTH_VERSION`; every other build says
 * {@link UNRELEASED_VERSION}, and so does a value that is not a release
 * version.
 */
export function releaseVersion(value: string | undefined = process.env['QAUTH_VERSION']): string {
  return value !== undefined && RELEASE_VERSION.test(value) ? value : UNRELEASED_VERSION;
}
