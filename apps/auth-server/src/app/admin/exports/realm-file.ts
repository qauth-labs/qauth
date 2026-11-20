import {
  canonicalRealmFile,
  hasUrlCredentials,
  REALM_FILE_FORMAT,
  type RealmFile,
  type RealmFileIssue,
  safeParseRealmFile,
} from '@qauth-labs/realm-file';

import { IMPORT_SECTIONS } from '../imports/plan';
import type { ImportSection, ImportState } from '../imports/section';

/**
 * THE EXPORT OF A REALM AS A REALM FILE (ADR-018 §5, ADR-019 Decision 11,
 * ADR-020 fork G, issue #530): the realm's configuration as the declarative
 * realm file (`urn:qauth:realm-file:v1-rc.0`, `@qauth-labs/realm-file`), the
 * inverse of the import plan (#518).
 *
 * {@link exportRealmFile} is pure: the realm as an import reads it
 * (`ImportState`, `../imports/state.ts`) in, the file out. The admin API's
 * `realms.export` (`./routes.ts`) serves it; the CLI's export (CFG-11) is a
 * client of that route, and a promotion from a sandbox (CFG-14) calls this
 * function on the sandbox's state.
 *
 * - **What it holds.** `format`, `realm` (the realm's name), and each section
 *   of `IMPORT_SECTIONS` its `export` writes: today the policies and the
 *   clients the operator manages. A section is added to the export where it
 *   is added to the import (`../imports/section.ts`), so the file holds
 *   only what an import plans, and imports back with no change. A section
 *   always says the whole of what it describes: a realm with no operator
 *   client exports `clients: []`.
 * - **No secret.** A secret policy field is left out, with no marker; no
 *   client's secret or private key member is read into the state. A client
 *   a developer owns, one that registered itself, a CIMD client, the system
 *   client and a service account's are not in the state's `clients`.
 * - **Environment-bound fields stay.** A client's `environment`, the
 *   realm's `posture.maxEnvironmentLaxity`, `http` and loopback redirect
 *   URIs: the file describes the realm as it is. A promotion leaves them out
 *   (CFG-14), not the export.
 * - **Canonical.** The file is in the format's canonical order
 *   (`canonicalRealmFile`): `format` and `realm` first, the sections in the
 *   format's order, each object's members in its schema's order, clients by
 *   `client_id`, every set sorted. Two exports of the same state are
 *   byte-identical as the format writes them (`serializeRealmFile`).
 * - **Valid, or refused.** The file is parsed as an import would parse it
 *   before it is returned. A realm that holds a value the format cannot
 *   hold (a stored URL with a user name or password, a client the seed
 *   manifest's rules refuse) is not exported at all: the error names each
 *   item and member at fault, never a value. A file the format refuses, or
 *   one that leaves part of the realm out, is never written.
 */

/** A realm whose state no valid realm file describes: every reason, by item and member. */
export class RealmFileExportError extends Error {
  override readonly name = 'RealmFileExportError';

  constructor(readonly issues: readonly RealmFileExportIssue[]) {
    super(
      `The realm cannot be exported as a realm file: ${issues.map((issue) => issue.message).join('; ')}`
    );
  }
}

/** One reason a realm cannot be exported. */
export interface RealmFileExportIssue {
  /** A JSON Pointer into the file the export would write (RFC 6901). */
  readonly pointer: string;
  /** What is wrong, naming the item (a client by its `client_id`) and never a value. */
  readonly message: string;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * An issue of the built file as the export says it: the item it is in,
 * named by its `client_id` where it has one, so the operator finds the
 * client to fix. A `client_id` that is itself a URL with a user name or
 * password is not quoted: the item is named by its place.
 */
function exportIssueOf(
  built: Record<string, unknown>,
  issue: RealmFileIssue
): RealmFileExportIssue {
  const [section, index, ...rest] = issue.path;
  const value = typeof section === 'string' ? built[section] : undefined;
  const entry = Array.isArray(value) && typeof index === 'number' ? value[index] : undefined;
  const clientId = isRecord(entry) ? entry['client_id'] : undefined;
  if (typeof clientId === 'string' && !hasUrlCredentials(clientId)) {
    const member = rest.length > 0 ? rest.join('.') : 'the entry';
    return {
      pointer: issue.pointer,
      message: `the ${String(section)} entry of client_id ${JSON.stringify(clientId)}, at ${member}: ${issue.message}`,
    };
  }
  return { pointer: issue.pointer, message: `${issue.pointer || '/'}: ${issue.message}` };
}

/**
 * The realm file that describes `state`: the sections of `sections` (the
 * import's, by default) each as its `export` writes it, parsed as an import
 * parses a file, in canonical order.
 *
 * @throws RealmFileExportError when the state holds a value the format
 *   cannot hold: no file is written in part
 */
export function exportRealmFile(
  state: ImportState,
  sections: readonly ImportSection[] = IMPORT_SECTIONS
): RealmFile {
  const built: Record<string, unknown> = { format: REALM_FILE_FORMAT, realm: state.realmName };
  for (const section of sections) {
    const value = section.export(state);
    if (value !== undefined) built[section.name] = value;
  }
  const parsed = safeParseRealmFile(built);
  if (!parsed.success) {
    throw new RealmFileExportError(parsed.issues.map((issue) => exportIssueOf(built, issue)));
  }
  return canonicalRealmFile(parsed.file);
}

/** The suffix of an exported file's name. */
export const REALM_FILE_SUFFIX = '.realm.json';

/** A file name character every system keeps as it is. */
const PORTABLE_NAME = /^[A-Za-z0-9._-]$/;

/**
 * A character of `filename*` (RFC 8187 §3.2.1 `attr-char`) left unencoded:
 * ALPHA, DIGIT and `!#$&+-.^_\`|~`. Every other byte is percent-encoded.
 */
const ATTR_CHAR = /^[A-Za-z0-9!#$&+\-.^_`|~]$/;

/** `value` as an RFC 8187 `ext-value`'s `value-chars`: UTF-8, percent-encoded. */
function extValue(value: string): string {
  let encoded = '';
  for (const byte of Buffer.from(value, 'utf8')) {
    const char = String.fromCharCode(byte);
    encoded +=
      byte < 0x80 && ATTR_CHAR.test(char)
        ? char
        : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return encoded;
}

/**
 * The `Content-Disposition` of an export (RFC 6266): an attachment named
 * `<realm>.realm.json`, so a browser saves the file under the realm's name.
 *
 * A realm's name is any string. `filename` carries it with each character
 * outside `A-Z a-z 0-9 . _ -` replaced by `_`, so the header never holds a
 * quote, a backslash, a path separator or a control character; when that
 * changed the name, `filename*` (RFC 8187) carries it whole, UTF-8 and
 * percent-encoded, and a browser prefers it. A name that is empty or only
 * dots names no file: it is saved as `realm.realm.json`.
 */
export function realmFileDisposition(realmName: string): string {
  if (/^\.*$/.test(realmName)) return `attachment; filename="realm${REALM_FILE_SUFFIX}"`;
  const portable = Array.from(realmName, (char) => (PORTABLE_NAME.test(char) ? char : '_')).join(
    ''
  );
  const name = `${portable}${REALM_FILE_SUFFIX}`;
  if (portable === realmName) return `attachment; filename="${name}"`;
  return `attachment; filename="${name}"; filename*=UTF-8''${extValue(`${realmName}${REALM_FILE_SUFFIX}`)}`;
}
