import {
  deepFreeze,
  type OperationRegistry,
  type RenderedField,
  type RenderInput,
} from '../../helpers/admin-operations';

/**
 * WHAT AN APPROVER IS SHOWN (ADR-019 Decisions 6 and 7, issue #512).
 *
 * The approver sees the operation rendered from the stored request, never
 * from text the requester wrote. Every security operation registers a
 * renderer (`render` in its definition), and {@link renderOperation} turns
 * its output into typed display data, never HTML. The requester's reason
 * comes apart, as quoted text attributed to the requester, and never as the
 * operation.
 *
 * Every string, the renderer's and the reason, follows the display rules of
 * ADR-019 Decision 6: it is length-capped, and it shows no control,
 * bidirectional or other invisible character. Each such character is shown
 * escaped, as `\u{202E}`, so the approver sees that the text held one and the
 * text cannot reorder or hide what the page shows around it. A backslash is
 * shown doubled, so a text that spells an escape out cannot pass for one, and
 * combining marks past the third on one character are shown escaped, so a
 * pile of them cannot spill over the lines around it.
 *
 * The display data goes to every reader of the approval: a renderer never
 * shows a secret value of the request, such as a password in its body.
 */

/** The length caps, in code points. A longer string ends in `…`. */
export const DISPLAY_LIMITS = Object.freeze({
  operation: 128,
  title: 200,
  label: 100,
  value: 1000,
  reason: 500,
  /** The most fields one rendered operation shows. */
  fields: 50,
});

/**
 * Code points a display string never carries as they are: controls (C0, DEL,
 * C1), format characters (the bidirectional embeddings, overrides, isolates
 * and marks, zero-width characters, the byte order mark, tag characters),
 * the line and paragraph separators, lone surrogates, every other code point
 * Unicode says to render as nothing (`Default_Ignorable_Code_Point`: the
 * Hangul fillers, the combining grapheme joiner, variation selectors), and
 * two that render blank or as a box, the blank Braille pattern and the object
 * replacement character.
 */
const UNSAFE_CODE_POINT =
  /^(?:[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u2800\ufffc]|\p{Cs})$/u;

/** A combining mark, which draws on the character before it. */
const COMBINING_MARK = /^\p{M}$/u;

/** The combining marks shown on one character; any after them is shown escaped. */
const MAX_COMBINING_MARKS = 3;

/** `codePoint` escaped: `\u{XXXX}`. */
function escaped(codePoint: string): string {
  const hex = (codePoint.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0');
  return `\\u{${hex}}`;
}

/** Each code point of `value` as it is shown: itself, doubled for a backslash, or escaped. */
function shownParts(value: string): string[] {
  const parts: string[] = [];
  let marks = 0;
  for (const codePoint of value) {
    if (UNSAFE_CODE_POINT.test(codePoint)) {
      parts.push(escaped(codePoint));
      marks = 0;
    } else if (COMBINING_MARK.test(codePoint)) {
      marks += 1;
      parts.push(marks > MAX_COMBINING_MARKS ? escaped(codePoint) : codePoint);
    } else {
      parts.push(codePoint === '\\' ? '\\\\' : codePoint);
      marks = 0;
    }
  }
  return parts;
}

const ELLIPSIS = '…';

/**
 * `value` as a display string: each unsafe code point escaped, a backslash
 * doubled, a fourth and later combining mark on one character escaped, and
 * the whole cut to `maxLength` code points, an escape never cut in two, with
 * `…` at the end when anything was cut.
 */
export function displayText(value: string, maxLength: number): string {
  const parts = shownParts(value);
  let length = 0;
  let out = '';
  for (const [index, part] of parts.entries()) {
    const partLength = Array.from(part).length;
    const last = index === parts.length - 1;
    // Room for the ellipsis, unless this is the last part and it fits.
    if (length + partLength > maxLength - (last ? 0 : 1)) {
      return `${out}${ELLIPSIS}`;
    }
    out += part;
    length += partLength;
  }
  return out;
}

/** A line of the display data. */
export interface DisplayField {
  readonly label: string;
  readonly value: string;
  readonly before?: string;
}

/** Text the requester wrote, shown as a quotation and never as the operation. */
export interface QuotedText {
  readonly type: 'quote';
  readonly source: 'requester';
  readonly text: string;
}

/** What the approval page shows of one approval: typed display data, never HTML. */
export interface OperationDisplay {
  /** The operation id. */
  readonly operation: string;
  readonly title: string;
  readonly fields: readonly DisplayField[];
  /** The requester's reason, quoted; `null` when there is none. */
  readonly reason: QuotedText | null;
}

/** A renderer that is missing, throws or returns anything but display data. */
export class ApprovalRenderError extends Error {
  override readonly name = 'ApprovalRenderError';
}

/** What {@link renderOperation} reads of an approval. */
export interface RenderableApproval {
  readonly operationId: string;
  /** The stored canonical request. */
  readonly canonicalRequest: Readonly<Record<string, unknown>>;
  readonly reason: string | null;
}

const isString = (value: unknown): value is string => typeof value === 'string';

/** `field` checked and shown, or an error. */
function displayField(field: unknown, index: number): DisplayField {
  if (typeof field !== 'object' || field === null || Array.isArray(field)) {
    throw new ApprovalRenderError(`field ${index} is not an object`);
  }
  const { label, value, before, ...rest } = field as Partial<RenderedField> &
    Record<string, unknown>;
  if (
    Object.keys(rest).length > 0 ||
    !isString(label) ||
    label === '' ||
    !isString(value) ||
    (before !== undefined && !isString(before))
  ) {
    throw new ApprovalRenderError(
      `field ${index} has a label, a value and maybe a before, each a string`
    );
  }
  return Object.freeze({
    label: displayText(label, DISPLAY_LIMITS.label),
    value: displayText(value, DISPLAY_LIMITS.value),
    ...(before === undefined ? {} : { before: displayText(before, DISPLAY_LIMITS.value) }),
  });
}

/**
 * The display data of `approval`, from the renderer its operation registers in
 * `registry`, run on a frozen copy of the stored request. Every string follows
 * the display rules ({@link displayText}); the reason is quoted.
 *
 * @throws {ApprovalRenderError} when the operation has no renderer, or its
 *   renderer throws or returns anything but a title and fields of strings
 */
export function renderOperation(
  approval: RenderableApproval,
  registry: Pick<OperationRegistry, 'get'>
): OperationDisplay {
  const render = registry.get(approval.operationId)?.render;
  if (render === undefined) {
    throw new ApprovalRenderError(`the operation ${approval.operationId} has no renderer`);
  }
  const stored = approval.canonicalRequest;
  const input: RenderInput = deepFreeze(
    structuredClone({
      operationId: approval.operationId,
      method: stored['method'],
      params: stored['params'],
      query: stored['query'],
      body: stored['body'],
    })
  ) as RenderInput;

  let rendered: unknown;
  try {
    rendered = render(input);
  } catch (error) {
    throw new ApprovalRenderError(
      `the renderer of ${approval.operationId} threw: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (typeof rendered !== 'object' || rendered === null || Array.isArray(rendered)) {
    throw new ApprovalRenderError(`the renderer of ${approval.operationId} returned no object`);
  }
  const { title, fields = [], ...rest } = rendered as Record<string, unknown>;
  if (Object.keys(rest).length > 0 || !isString(title) || title === '' || !Array.isArray(fields)) {
    throw new ApprovalRenderError(
      `the renderer of ${approval.operationId} returns a title and a list of fields, nothing else`
    );
  }
  if (fields.length > DISPLAY_LIMITS.fields) {
    throw new ApprovalRenderError(
      `the renderer of ${approval.operationId} returned more than ${DISPLAY_LIMITS.fields} fields`
    );
  }

  return Object.freeze({
    operation: displayText(approval.operationId, DISPLAY_LIMITS.operation),
    title: displayText(title, DISPLAY_LIMITS.title),
    fields: Object.freeze(fields.map(displayField)),
    reason:
      approval.reason === null
        ? null
        : Object.freeze({
            type: 'quote' as const,
            source: 'requester' as const,
            text: displayText(approval.reason, DISPLAY_LIMITS.reason),
          }),
  });
}
