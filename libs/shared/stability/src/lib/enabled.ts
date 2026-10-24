import type { ExperimentalItem } from './item';
import { type BuiltServerItemId, EXPERIMENTAL_ITEMS } from './items';

/** The docs page that lists every experimental item, on the docs site. */
export const EXPERIMENTAL_FEATURES_PAGE_URL =
  'https://docs.qauth.dev/reference/experimental-features/';

/**
 * The heading anchor Starlight renders for an ASCII heading, as its slugger
 * computes it: `oid4vp-1.0-base` becomes `oid4vp-10-base`.
 */
export function headingAnchor(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9 _-]/g, '')
    .replace(/ /g, '-');
}

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

/**
 * The configuration keys that switch a server item on. Such a key warns at
 * boot through its item, once the item is on, rather than on its own.
 */
export function serverSwitchKeys(
  items: readonly ExperimentalItem[] = EXPERIMENTAL_ITEMS
): ReadonlySet<string> {
  return new Set(
    items.flatMap((item) =>
      item.surface === 'server' && item.switchKey !== null ? [item.switchKey] : []
    )
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
