import { fullFormats } from 'ajv-formats/dist/formats';

/**
 * The `uri` and `date-time` checks of ajv-formats, in its full mode: the
 * checks the published step schemas are validated with. The Zod schemas run
 * them beside each pattern (`zod-kit.ts`), so a value with a format passes the
 * server's check exactly when it passes the published schema's.
 */

const uriFormat = fullFormats.uri;
const dateTimeFormat = fullFormats['date-time'];

if (typeof uriFormat !== 'function')
  throw new Error('ajv-formats: the uri format is not a function');
if (
  typeof dateTimeFormat !== 'object' ||
  dateTimeFormat === null ||
  !('validate' in dateTimeFormat) ||
  typeof dateTimeFormat.validate !== 'function'
) {
  throw new Error('ajv-formats: the date-time format has no validate function');
}

const validateUri = uriFormat as (value: string) => boolean;
const validateDateTime = dateTimeFormat.validate as (value: string) => boolean;

/** An absolute URI as RFC 3986 §3 defines it. */
export function isUri(value: string): boolean {
  return validateUri(value);
}

/** An RFC 3339 §5.6 `date-time`: a real date and time, not only digits in place. */
export function isDateTime(value: string): boolean {
  return validateDateTime(value);
}
