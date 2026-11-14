/**
 * THE DEVICE LABEL of a session (#1110): the account contract's `Device.label`,
 * "a label from the user agent, such as `Firefox on Linux`".
 *
 * The label names a browser and a system read from the `User-Agent` the
 * sign-in sent, each from a fixed list below, and never repeats the header's
 * own text: the header is whatever the device declared, so a label built from
 * it only by recognition is always display text, short, and free of markup.
 * A header that names neither is {@link UNKNOWN_DEVICE_LABEL}.
 *
 * Recognition, not identification: a browser may claim to be another, and the
 * label says only what it claimed. Order matters where one header names
 * several: Edge, Opera and Samsung Internet also name Chrome and Safari, and
 * Chrome also names Safari; an iPhone or iPad also names Mac OS X, and Android
 * also names Linux.
 */

/** The label of a session whose `User-Agent` names no browser and no system this list knows. */
export const UNKNOWN_DEVICE_LABEL = 'Unknown device';

/** One entry of a list: every pattern must match, each a plain token, so no match backtracks. */
type Recognised = readonly [readonly RegExp[], string];

/** The browsers recognised, the first match winning. */
const BROWSERS: readonly Recognised[] = [
  [[/\bEdg(?:e|A|iOS)?\//], 'Edge'],
  [[/\b(?:OPR|OPiOS|Opera)\b/], 'Opera'],
  [[/\bSamsungBrowser\//], 'Samsung Internet'],
  [[/\b(?:Firefox|FxiOS)\//], 'Firefox'],
  [[/\bChromium\//], 'Chromium'],
  [[/\b(?:Chrome|CriOS)\//], 'Chrome'],
  [[/\bVersion\//, /\bSafari\//], 'Safari'],
];

/** The systems recognised, the first match winning. */
const SYSTEMS: readonly Recognised[] = [
  [[/\biPhone\b/], 'iPhone'],
  [[/\biPad\b/], 'iPad'],
  [[/\bAndroid\b/], 'Android'],
  [[/\bCrOS\b/], 'ChromeOS'],
  [[/\bWindows\b/], 'Windows'],
  [[/\b(?:Macintosh|Mac OS X)\b/], 'macOS'],
  [[/\bLinux\b/], 'Linux'],
];

/** The longest header read: the length a session stores it at (`eventRequest`). */
const USER_AGENT_MAX_LENGTH = 1024;

function firstMatch(text: string, list: readonly Recognised[]): string | null {
  for (const [patterns, name] of list) {
    if (patterns.every((pattern) => pattern.test(text))) return name;
  }
  return null;
}

/**
 * The label of a session that signed in with `userAgent`: `<browser> on
 * <system>`, the browser or the system alone when only one is recognised, or
 * {@link UNKNOWN_DEVICE_LABEL}.
 */
export function deviceLabelOf(userAgent: string | null | undefined): string {
  if (typeof userAgent !== 'string' || userAgent.length === 0) return UNKNOWN_DEVICE_LABEL;
  const text = userAgent.slice(0, USER_AGENT_MAX_LENGTH);
  const browser = firstMatch(text, BROWSERS);
  const system = firstMatch(text, SYSTEMS);
  if (browser !== null && system !== null) return `${browser} on ${system}`;
  return browser ?? system ?? UNKNOWN_DEVICE_LABEL;
}
