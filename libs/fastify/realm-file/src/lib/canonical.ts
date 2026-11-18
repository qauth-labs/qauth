import type { RealmFile } from './realm-file';
import { REALM_FILE_SECTIONS } from './sections';

/**
 * The canonical order of a realm file (#515), so two files of the same
 * configuration compare cleanly as text: `format` and `realm` first, then the
 * sections in {@link REALM_FILE_SECTIONS} order, each list of entries sorted
 * by its natural key, and every array that is a set (a client's scopes and
 * redirect URIs, a policy field the registry declares a set) sorted, each
 * value once. Strings sort by UTF-16 code unit, as RFC 8785 sorts members.
 * Arrays whose order means something, such as a JWK's certificate chain,
 * stay as written. A file QAuth writes is in this order; a file a person
 * writes may be in any.
 */
export function canonicalRealmFile(file: RealmFile): RealmFile {
  const canonical: Record<string, unknown> = { format: file.format, realm: file.realm };
  for (const section of REALM_FILE_SECTIONS) {
    const value = (file as unknown as Record<string, unknown>)[section.name];
    if (value !== undefined) canonical[section.name] = section.canonical(value);
  }
  return canonical as unknown as RealmFile;
}

/** The text of `file` in canonical order: two-space JSON with a final newline. */
export function serializeRealmFile(file: RealmFile): string {
  return `${JSON.stringify(canonicalRealmFile(file), null, 2)}\n`;
}
