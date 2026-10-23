import type { ConfigKey, KeyDefault, KeyOwner, KeyTier } from './types';
import { KEY_TIERS } from './types';

/** Where the generated page lives, relative to the repository root. */
export const CONFIGURATION_PAGE_PATH = 'apps/docs-site/src/content/docs/operate/configuration.md';

/**
 * The page's `lastVerified` date. The registry test regenerates and checks the
 * page on every run, so this changes only when the page's own prose does.
 */
const LAST_VERIFIED = '2026-10-20';

/** The areas, in the order each tier's section lists them. */
const OWNER_HEADINGS: Readonly<Record<KeyOwner, string>> = {
  server: 'Server',
  observability: 'Logs and metrics',
  storage: 'Database and Redis',
  realms: 'Realms',
  tokens: 'Tokens',
  signing: 'Signing',
  'key-custody': 'Keys and secrets',
  accounts: 'Accounts and passwords',
  sessions: 'Browser sessions',
  mail: 'Mail',
  'client-registration': 'Client registration',
  'id-jag': 'Enterprise-managed authorization (ID-JAG)',
  passkeys: 'Passkeys',
  'wallet-federation': 'Wallet federation',
  'rate-limits': 'Rate limits',
  'developer-portal': 'Developer portal',
  testing: 'Testing',
};

const TIER_HEADINGS: Readonly<Record<KeyTier, string>> = {
  stable: 'Stable keys',
  advanced: 'Advanced keys',
  experimental: 'Experimental keys',
};

const ADR_018 = '/reference/records/adr/018-1-0-scope-and-stability/';
const ADR_019 = '/reference/records/adr/019-deployment-topology-and-trust-boundaries/';

function code(value: string): string {
  return `\`${value}\``;
}

function table(header: readonly string[], rows: readonly (readonly string[])[]): string {
  return [header, header.map(() => '---'), ...rows]
    .map((cells) => `| ${cells.join(' | ')} |`)
    .join('\n');
}

/** A key's default as the page prints it. A secret's literal value never appears. */
export function describeDefault(key: Pick<ConfigKey, 'default' | 'secret'>): string {
  const value: KeyDefault = key.default;
  if (value === null) return 'unset';
  if (typeof value === 'object') return 'required' in value ? 'required' : value.computed;
  if (key.secret) return 'not shown';
  return value === '' ? 'empty' : code(value);
}

function describeRole(key: ConfigKey): string {
  return key.seeds === undefined ? key.role : `${key.role}: ${code(key.seeds)}`;
}

function describeKey(key: ConfigKey): string {
  const notes = [key.docs];
  if (key.secret) notes.push('Secret.');
  if (key.developmentOnly) notes.push('Development only.');
  if (key.experimentalValues.length > 0) {
    notes.push(`Experimental values: ${key.experimentalValues.map(code).join(', ')}.`);
  }
  if (key.aliases.length > 0) {
    notes.push(`Old name: ${key.aliases.map((alias) => code(alias.name)).join(', ')}.`);
  }
  return notes.join(' ');
}

function byName(a: ConfigKey, b: ConfigKey): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

function tierSection(tier: KeyTier, keys: readonly ConfigKey[]): string[] {
  const lines = [`## ${TIER_HEADINGS[tier]}`, ''];
  if (keys.length === 0) {
    lines.push(`No key is ${tier}.`, '');
    return lines;
  }
  for (const [owner, heading] of Object.entries(OWNER_HEADINGS)) {
    const owned = keys.filter((key) => key.owner === owner).sort(byName);
    if (owned.length === 0) continue;
    lines.push(
      `### ${heading}`,
      '',
      table(
        ['Key', 'Role', 'Default', 'Since', 'Description'],
        owned.map((key) => [
          code(key.name),
          describeRole(key),
          describeDefault(key),
          key.since,
          describeKey(key),
        ])
      ),
      ''
    );
  }
  return lines;
}

function experimentalValuesSection(registry: readonly ConfigKey[]): string[] {
  const keys = registry.filter((key) => key.experimentalValues.length > 0).sort(byName);
  if (keys.length === 0) return [];
  return [
    '### Experimental values',
    '',
    'These values of stable and advanced keys are experimental, and the server warns at boot when one is set.',
    '',
    table(
      ['Key', 'Experimental values'],
      keys.map((key) => [code(key.name), key.experimentalValues.map(code).join(', ')])
    ),
    '',
  ];
}

function aliasSection(registry: readonly ConfigKey[]): string[] {
  const rows = registry
    .flatMap((key) =>
      key.aliases.map((alias) => [code(alias.name), code(key.name), alias.deprecatedSince])
    )
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const lines = ['## Renamed keys', ''];
  if (rows.length === 0) {
    lines.push('No key has been renamed.', '');
    return lines;
  }
  lines.push(
    'A renamed key keeps working under its old name for the deprecation window.',
    '',
    '- Only the old name is set: the server uses its value and logs a warning at boot.',
    '- Both names are set to the same value: the server logs a warning at boot.',
    '- Both names are set to different values: the server refuses to start, and the error names both.',
    '',
    table(['Old name', 'Use instead', 'Deprecated since'], rows),
    ''
  );
  return lines;
}

/**
 * Render the configuration page (`operate/configuration.md`) from the registry:
 * stable keys first, then advanced, then experimental, then renamed keys.
 *
 * The output is Markdown that Prettier may still realign; the registry test
 * formats it before comparing it with the committed page.
 */
export function renderConfigurationPage(registry: readonly ConfigKey[]): string {
  const lines = [
    '---',
    'title: Configuration',
    'description: Every environment key QAuth reads, with its stability tier, role, default and meaning.',
    'sidebar:',
    '  order: 8',
    `lastVerified: '${LAST_VERIFIED}'`,
    '---',
    '',
    '<!-- Generated from libs/server/config/src/lib/registry by its tests. Do not edit by hand: change the registry and run `pnpm nx test server-config -- -u`. -->',
    '',
    'QAuth reads its configuration from environment variables. This page lists every QAuth key the auth server and the developer portal read, generated from the configuration key registry in `libs/server/config/src/lib/registry/`. A test fails when the page, the registry and the env schemas disagree. Variables of the Node.js runtime itself, such as `UV_THREADPOOL_SIZE`, are not listed.',
    '',
    '## Stability tiers',
    '',
    `Every key has a tier, which says how it may change ([ADR-018 §5](${ADR_018})).`,
    '',
    '- **Stable** keys follow the deprecation policy. A deprecation is announced in a minor release; the old name or behaviour keeps working, with a warning at boot, for at least 12 months, and it is removed only in a new major release.',
    '- **Advanced** keys may change in a minor release. Read the release notes before you upgrade a deployment that sets one.',
    '- **Experimental** keys may change at any time, without a deprecation window. The server logs a warning at boot for each experimental key that is set, and for each key set to an experimental value.',
    '',
    '## Roles',
    '',
    `Every key has a role, which says who owns its value ([ADR-019 Decision 10](${ADR_019})).`,
    '',
    '- **deployment**: the environment owns the value, for the whole deployment.',
    "- **realm-seed**: a realm policy. Once realm policies live on the realm row, the key only seeds a new realm's default, and the realm row owns the value from then on. Until then the server reads the key for every realm, unless its description says it already seeds the realm row. The Role column names the policy the key seeds.",
    '',
    'A key marked **Secret** holds a credential. This page never shows its value, not even as a default, and neither does the boot log.',
    '',
  ];

  for (const tier of KEY_TIERS) {
    lines.push(
      ...tierSection(
        tier,
        registry.filter((key) => key.tier === tier)
      )
    );
    if (tier === 'experimental') {
      lines.push(...experimentalValuesSection(registry));
    }
  }

  lines.push(
    ...aliasSection(registry),
    '## Adding a key',
    '',
    'A pull request that adds, renames or removes a key registers the change in the same pull request: an entry in `libs/server/config/src/lib/registry/keys/`, with its tier, role, default and one sentence, and a regenerated page. A stable key also appears in `.env.example`. A test fails until all three agree.',
    ''
  );

  return lines.join('\n');
}
