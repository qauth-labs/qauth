import type {
  RealmPolicySetting,
  RealmPolicySettingsFile,
  SettingDirection,
  SettingSecurityWhen,
} from '@qauth-labs/shared-admin-settings';

import { directionKind, isOneSentence, PolicyDefinitionError } from './field';
import { changeClassOf, type PolicyRegistry } from './registry';

/**
 * The settings metadata of the admin console (ADR-020 §5 criteria 1 and 2,
 * issue #589), generated from the registry: for each field, its path, its
 * one-sentence explanation, its docs link, its default, its direction and
 * what a change of it needs. The console imports the generated file from
 * `@qauth-labs/shared-admin-settings`, since it cannot import this library.
 *
 * Generated, never edited by hand: `pnpm nx test server-realm-policy -- -u`
 * rewrites the file, and `settings.test.ts` fails while the committed file
 * differs. It stays plain `JSON.stringify` output, which `.oxfmtrc.json`
 * leaves alone.
 */

/** The generated file, from the repository root. */
export const REALM_POLICY_SETTINGS_PATH =
  'libs/shared/admin-settings/src/lib/realm-policy-settings.json';

/** An absolute link into the docs site. */
const DOCS_LINK_PATTERN = /^https:\/\/docs\.qauth\.dev\/[^\s]*$/;

/**
 * The settings metadata of `registry`.
 *
 * @throws PolicyDefinitionError naming the field when one has no one-sentence
 *   explanation, no docs link, or, not being a secret, no default. A field
 *   made by `policyField` has all three; a field of another copy of this
 *   library, or one built by hand, is held to the same rule here.
 */
export function realmPolicySettings(
  registry: Pick<PolicyRegistry, 'version' | 'fields'>
): RealmPolicySettingsFile {
  const settings = registry.fields().map(({ path, field }): RealmPolicySetting => {
    const doc: unknown = field.doc;
    const summary = (doc as { summary?: unknown } | null)?.summary;
    const link = (doc as { link?: unknown } | null)?.link;
    if (!isOneSentence(summary)) {
      throw new PolicyDefinitionError(`${path} has no one-sentence explanation (doc.summary)`);
    }
    if (typeof link !== 'string' || !DOCS_LINK_PATTERN.test(link)) {
      throw new PolicyDefinitionError(`${path} has no https://docs.qauth.dev/ link (doc.link)`);
    }
    if (!field.secret && (!Object.hasOwn(field, 'default') || field.default === undefined)) {
      throw new PolicyDefinitionError(`${path} has no default`);
    }
    const { direction, securityWhen } = field;
    return {
      path,
      summary,
      docs: link,
      default: field.secret ? null : structuredClone(field.default),
      secret: field.secret,
      direction: directionKind(direction) as SettingDirection,
      ...(typeof direction === 'string' ? {} : { order: [...direction.order] }),
      securityWhen: securityWhen as SettingSecurityWhen,
      class: {
        tightening: changeClassOf(securityWhen, 'tightening'),
        loosening: changeClassOf(securityWhen, 'loosening'),
        neutral: changeClassOf(securityWhen, 'neutral'),
      },
      effects: [...field.effects],
      environmentBound: field.environmentBound,
    };
  });
  return {
    policySchemaVersion: registry.version,
    description:
      'The realm policy settings, generated from the realm policy schema (libs/server/realm-policy): what the admin console shows beside each setting. Never edited by hand.',
    settings,
  };
}

/** The generated file's text: plain `JSON.stringify` output, two spaces, a final newline. */
export function realmPolicySettingsText(registry: Pick<PolicyRegistry, 'version' | 'fields'>) {
  return `${JSON.stringify(realmPolicySettings(registry), null, 2)}\n`;
}
