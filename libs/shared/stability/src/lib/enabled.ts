import { headingAnchor } from './anchor';
import type { ExperimentalItem } from './item';
import { type BuiltServerItemId, EXPERIMENTAL_ITEMS } from './items';

/** The docs page that lists every experimental item, on the docs site. */
export const EXPERIMENTAL_FEATURES_PAGE_URL =
  'https://docs.qauth.dev/reference/experimental-features/';

/** The link to an item's section of the docs page. */
export function experimentalDocsUrl(item: Pick<ExperimentalItem, 'id'>): string {
  return `${EXPERIMENTAL_FEATURES_PAGE_URL}#${headingAnchor(item.id)}`;
}

/**
 * How the auth server tells, from its parsed configuration, that each built
 * server item is on. The type names every built server item, so building one
 * without telling the server how to read its switch fails to compile.
 */
export type ExperimentalSwitches<Config> = {
  readonly [Id in BuiltServerItemId]: (config: Config) => boolean;
};

/**
 * The items whose switch is on, in registry order. An item that is not built,
 * or that runs in an SDK, is never on here: the server has no switch for it.
 */
export function enabledExperimentalItems<Config>(
  config: Config,
  switches: ExperimentalSwitches<Config>,
  items: readonly ExperimentalItem[] = EXPERIMENTAL_ITEMS
): readonly ExperimentalItem[] {
  const isOn = switches as Readonly<Record<string, ((config: Config) => boolean) | undefined>>;
  return items.filter(
    (item) => item.built && item.surface === 'server' && isOn[item.id]?.(config) === true
  );
}

/** A configuration setting that has an experimental warning of its own. */
export interface ExperimentalSetting {
  /** The configuration key. */
  readonly key: string;
  /** Its value in the environment, `undefined` when unset. */
  readonly value: string | undefined;
  /** The key is experimental as a whole, not only some of its values. */
  readonly experimentalKey: boolean;
}

/**
 * Whether a setting is the switch of a built server item. Its own experimental
 * warning is then left out, because the item warns instead, once it is on.
 *
 * A key that is experimental as a whole matches whatever its value; a key
 * with experimental values matches only the item's own value, so another
 * experimental value of the same key keeps its warning. An item that is not
 * built has no switch the server reads, so its key keeps its warning too.
 */
export function switchesExperimentalFeature(
  setting: ExperimentalSetting,
  items: readonly ExperimentalItem[] = EXPERIMENTAL_ITEMS
): boolean {
  const value = setting.value?.trim();
  return items.some(
    (item) =>
      item.built &&
      item.surface === 'server' &&
      item.switchKey === setting.key &&
      (setting.experimentalKey || item.switchValue === value)
  );
}

/** One boot warning: the server logs one per enabled item (ADR-018 §5). */
export interface ExperimentalBootWarning {
  /** The item's id. */
  readonly id: string;
  /** Its section of the docs page. */
  readonly docs: string;
  /** The log line. */
  readonly message: string;
}

/** The boot warning of an item that is on. */
export function experimentalBootWarning(item: ExperimentalItem): ExperimentalBootWarning {
  const docs = experimentalDocsUrl(item);
  return {
    id: item.id,
    docs,
    message: `Experimental feature ${item.id} is on. It may change in a minor release, without a deprecation window. See ${docs}`,
  };
}
