/**
 * Parsing the referencing credential's `status` claim (issue #297).
 *
 * ## The narrow input this module exists to define
 *
 * Status checking takes ONE thing from a credential: the `status` claim, as it
 * came off the validated payload. It does not take the credential, the
 * presentation, or the SD-JWT VC parser's output — deliberately. #234 owns
 * presentation validation in a parallel lane; a status checker that reached
 * into that shape would couple two independently-evolving parsers and would
 * make this module untestable without building a whole presentation.
 *
 * So the seam is `unknown` in, {@link StatusListReference} out. The caller
 * hands over `claims.status` and gets back either a usable reference or
 * nothing.
 *
 * ## HAIP §6.1: `status` present means `status_list`
 *
 * draft-14 §5.2 allows `status` to hold several mechanisms and requires at
 * least one. HAIP §6.1 narrows that: when a credential carries `status` it MUST
 * be `status_list`. This parser implements the HAIP reading, which is also the
 * fail-closed one — a `status` claim naming some mechanism we cannot evaluate
 * is a credential whose status we cannot establish, and per #297 that is a
 * rejection, not a shrug.
 */

/**
 * Longest `uri` accepted, in characters.
 *
 * The value is fetched and is compared byte-for-byte against the token's `sub`,
 * so an unbounded string is both an outbound-request lever and a comparison
 * cost an attacker controls.
 */
const MAX_STATUS_LIST_URI_LENGTH = 2048;

/**
 * A usable `status_list` reference, extracted from a credential's `status`
 * claim.
 *
 * `uri` is the RAW string as the issuer wrote it, NOT a canonicalized form.
 * That is a requirement, not an oversight: draft-14 §6 makes the Relying Party
 * check that the Status List Token's `sub` equals *"the `uri` claim in the
 * `status_list` object of the Referenced Token"*. Canonicalizing here would
 * compare a reduced form against an unreduced `sub` and either reject valid
 * tokens or, if the reduction were applied to both sides, accept a `sub` that
 * merely normalises to the same value. The URI is validated for SHAPE
 * (`status-list-uri.ts`) and left otherwise untouched.
 */
export interface StatusListReference {
  /** `status.status_list.idx` — the entry index within the list. */
  readonly idx: number;
  /** `status.status_list.uri` — verbatim; identifies the Status List Token. */
  readonly uri: string;
}

/** Whether `value` is a plain, non-array object we can read members from. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Extract the `status_list` reference from a credential's `status` claim.
 *
 * Never throws and never distinguishes its failures: every malformed shape
 * returns `undefined`, and the caller turns that into the single refusal. A
 * thrown parse error here would be a 500 for an attacker-controlled payload,
 * and a per-shape error would be an oracle.
 *
 * Rejected, each on purpose:
 *
 *  - a `status` claim that is not an object, or carries no `status_list`;
 *  - `idx` that is not a non-negative SAFE integer — `2**53` and above stop
 *    being exact, so a "large index" could alias a small one after arithmetic,
 *    and a negative index would read backwards out of the byte array;
 *  - `uri` that is not a string, is blank, or exceeds
 *    {@link MAX_STATUS_LIST_URI_LENGTH}.
 *
 * URI *shape* (scheme, host, userinfo, fragment) is NOT checked here — that is
 * `isPermittedStatusListUri`'s job, because it is an SSRF decision that depends
 * on operator configuration rather than on the claim being well-formed.
 *
 * @param status - the credential's `status` claim value, as parsed JSON.
 * @returns the reference, or `undefined` when there is not a usable one.
 */
export function parseStatusListReference(status: unknown): StatusListReference | undefined {
  if (!isRecord(status)) return undefined;

  const statusList = status['status_list'];
  if (!isRecord(statusList)) return undefined;

  const idx = statusList['idx'];
  if (typeof idx !== 'number' || !Number.isSafeInteger(idx) || idx < 0) return undefined;

  const uri = statusList['uri'];
  if (typeof uri !== 'string') return undefined;

  const trimmed = uri.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_STATUS_LIST_URI_LENGTH) return undefined;

  // The TRIMMED value is what is both fetched and compared against `sub`, so
  // the two can never diverge — whitespace is removed once, here, rather than
  // by whichever consumer happens to think of it.
  return Object.freeze({ idx, uri: trimmed });
}
