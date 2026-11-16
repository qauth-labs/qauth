/**
 * The identifier of the declarative realm file's format (ADR-018 §5, #515),
 * and the paths it is published at.
 *
 * Until QAuth 1.0.0 the format is a release candidate, `v1-rc.<M>`: a breaking
 * change raises `<M>`, so an identifier never names two formats. The release
 * that ships 1.0.0 drops the suffix, and `urn:qauth:realm-file:v1` is the
 * promise; a breaking change after it needs `v2`.
 */

/** The format this server reads and writes. */
export const REALM_FILE_FORMAT = 'urn:qauth:realm-file:v1-rc.0';

/** The format's version, as file names carry it: `v1-rc.0`. */
export const REALM_FILE_FORMAT_VERSION = REALM_FILE_FORMAT.slice(
  REALM_FILE_FORMAT.lastIndexOf(':') + 1
);

/** The published JSON Schema, from the repository root (the docs site's `public/`). */
export const REALM_FILE_SCHEMA_PATH = `apps/docs-site/public/schemas/realm-file-${REALM_FILE_FORMAT_VERSION}.json`;

/** The JSON Schema's `$id`: where the docs site serves it. */
export const REALM_FILE_SCHEMA_ID = `https://docs.qauth.dev/schemas/realm-file-${REALM_FILE_FORMAT_VERSION}.json`;

/** The command that writes the JSON Schema; the stable-surface registry names it. */
export const REALM_FILE_EXPORT_COMMAND =
  'pnpm exec nx run realm-file:schema-export --skip-nx-cache';

/** The docs page that describes the format, from the repository root. */
export const REALM_FILE_PAGE_PATH = 'apps/docs-site/src/content/docs/reference/realm-file.md';
