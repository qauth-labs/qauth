import { describe, expect, it } from 'vitest';

import { MAX_AUTH_METHOD_PLUGINS, pluginsEnvSchema } from './plugins';

describe('pluginsEnvSchema (#600)', () => {
  it('loads no plugin and keeps the plugin API off by default', () => {
    expect(pluginsEnvSchema.parse({})).toEqual({
      AUTH_METHOD_PLUGINS: [],
      PLUGIN_API_ENABLED: false,
    });
    expect(pluginsEnvSchema.parse({ AUTH_METHOD_PLUGINS: '  ', PLUGIN_API_ENABLED: '' })).toEqual({
      AUTH_METHOD_PLUGINS: [],
      PLUGIN_API_ENABLED: false,
    });
  });

  it('reads package names in the order written, trimmed', () => {
    const parsed = pluginsEnvSchema.parse({
      AUTH_METHOD_PLUGINS: ' @example/qauth-plugin-corp-sso , qauth-plugin-partner.v2 ',
      PLUGIN_API_ENABLED: 'true',
    });
    expect(parsed.AUTH_METHOD_PLUGINS).toEqual([
      '@example/qauth-plugin-corp-sso',
      'qauth-plugin-partner.v2',
    ]);
    expect(Object.isFrozen(parsed.AUTH_METHOD_PLUGINS)).toBe(true);
    expect(parsed.PLUGIN_API_ENABLED).toBe(true);
  });

  it.each([
    ['a relative path', './plugins/corp-sso'],
    ['an absolute path', '/opt/plugins/corp-sso'],
    ['a URL', 'https://plugins.example/corp-sso.tgz'],
    ['a file specifier', 'file:../corp-sso'],
    ['a git specifier', 'git+https://example.com/corp-sso.git'],
    ['a version range', 'corp-sso@1.2.3'],
    ['an upper-case name', 'Corp-SSO'],
    ['a name that starts with a dot', '.corp-sso'],
    ['an empty entry', 'corp-sso,,partner'],
    ['a trailing comma', 'corp-sso,'],
    ['a name with a space', 'corp sso'],
    ['a name too long for npm', `a${'b'.repeat(214)}`],
  ])('refuses %s', (_case, value) => {
    expect(pluginsEnvSchema.safeParse({ AUTH_METHOD_PLUGINS: value }).success).toBe(false);
  });

  it('refuses a package listed twice', () => {
    const parsed = pluginsEnvSchema.safeParse({ AUTH_METHOD_PLUGINS: 'corp-sso, corp-sso' });
    expect(parsed.success).toBe(false);
    expect(parsed.error?.issues.map((issue) => issue.message)).toContain(
      'AUTH_METHOD_PLUGINS lists a package twice'
    );
  });

  it(`refuses more than ${MAX_AUTH_METHOD_PLUGINS} packages`, () => {
    const names = Array.from({ length: MAX_AUTH_METHOD_PLUGINS + 1 }, (_, index) => `p${index}`);
    expect(pluginsEnvSchema.safeParse({ AUTH_METHOD_PLUGINS: names.join(',') }).success).toBe(
      false
    );
    expect(
      pluginsEnvSchema.safeParse({ AUTH_METHOD_PLUGINS: names.slice(1).join(',') }).success
    ).toBe(true);
  });

  it('refuses a switch value other than true or false', () => {
    for (const value of ['1', 'yes', 'TRUE', 'on']) {
      expect(pluginsEnvSchema.safeParse({ PLUGIN_API_ENABLED: value }).success).toBe(false);
    }
  });
});
