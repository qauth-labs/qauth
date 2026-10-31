import { describe, expect, it } from 'vitest';

import { type AdminOperation, type RenderInput } from '../../helpers/admin-operations';
import {
  ApprovalRenderError,
  DISPLAY_LIMITS,
  displayText,
  type RenderableApproval,
  renderOperation,
} from './display';

/**
 * WHAT AN APPROVER IS SHOWN (#512, ADR-019 Decision 6): typed display data
 * from the operation's renderer, every string capped and stripped of control,
 * bidirectional and invisible characters, and the requester's reason quoted
 * apart from the operation.
 */

/** What no shown string holds: controls, bidirectional and zero-width characters. */
// eslint-disable-next-line no-control-regex -- matching control characters is the entire purpose of this pattern
const UNSAFE_SHOWN = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/;

const RLO = '\u202e';
const LRI = '\u2066';
const ZWSP = '\u200b';

/** A registry of one operation whose renderer is `render`. */
function registryOf(render: AdminOperation['render'] | undefined) {
  const operation = { id: 'keys.rotate', render } as unknown as AdminOperation;
  return { get: (id: string) => (id === operation.id ? operation : undefined) };
}

const APPROVAL: RenderableApproval = {
  operationId: 'keys.rotate',
  canonicalRequest: {
    operationId: 'keys.rotate',
    method: 'POST',
    params: { realmId: 'r', keyId: `signing${RLO}1` },
    query: {},
    body: { comment: `rotate${LRI}now` },
  },
  reason: `Please approve <b>now</b>${RLO}gnp.exe\n`,
};

const rotate = (request: RenderInput) => {
  const params = request.params as { keyId: string };
  const body = request.body as { comment: string };
  return {
    title: `Rotate the signing key ${params.keyId}`,
    fields: [
      { label: 'Key', value: params.keyId },
      { label: 'Comment', value: body.comment, before: `old${ZWSP}` },
    ],
  };
};

describe('the display rules (#512, ADR-019 Decision 6)', () => {
  // Acceptance criterion: the renderer output escapes control and
  // bidirectional characters and quotes the reason.
  it('escapes control and bidirectional characters in the output and quotes the reason', () => {
    const display = renderOperation(APPROVAL, registryOf(rotate));
    expect(display).toEqual({
      operation: 'keys.rotate',
      title: 'Rotate the signing key signing\\u{202E}1',
      fields: [
        { label: 'Key', value: 'signing\\u{202E}1' },
        { label: 'Comment', value: 'rotate\\u{2066}now', before: 'old\\u{200B}' },
      ],
      reason: {
        type: 'quote',
        source: 'requester',
        text: 'Please approve <b>now</b>\\u{202E}gnp.exe\\u{000A}',
      },
    });
    // Nothing the page shows holds such a character, and the reason never
    // reaches the operation's own lines.
    const shown = JSON.stringify(display);
    expect(shown).not.toMatch(UNSAFE_SHOWN);
    expect([display.title, ...display.fields.map((field) => field.value)].join(' ')).not.toContain(
      'Please approve'
    );
    expect(Object.isFrozen(display)).toBe(true);
  });

  it('shows no reason when the requester gave none', () => {
    expect(renderOperation({ ...APPROVAL, reason: null }, registryOf(rotate)).reason).toBeNull();
  });

  it('escapes every control, format and separator character, and a lone surrogate', () => {
    for (const unsafe of [
      '\u0000',
      '\u0007',
      '\u001b',
      '\u007f',
      '\u0085',
      '\u00ad',
      '\u061c',
      '\u200e',
      '\u200f',
      '\u202a',
      '\u202d',
      '\u2028',
      '\u2029',
      '\u2069',
      '\ufeff',
      '\u{e0041}',
      '\ud800',
      '\udc00',
    ]) {
      const shown = displayText(`a${unsafe}b`, 100);
      expect(shown, JSON.stringify(unsafe)).toMatch(/^a\\u\{[0-9A-F]{4,5}\}b$/);
    }
    // Code points Unicode renders as nothing, outside the classes above.
    for (const codePoint of [0x3164, 0x115f, 0xffa0, 0x034f, 0xfe00, 0xfe0f, 0x180b, 0xe0100]) {
      const shown = displayText(`a${String.fromCodePoint(codePoint)}b`, 100);
      expect(shown, codePoint.toString(16)).toBe(
        `a\\u{${codePoint.toString(16).toUpperCase().padStart(4, '0')}}b`
      );
    }
    // Letters, emoji and combining marks stay as they are.
    expect(displayText('Zürich 🔑 é', 100)).toBe('Zürich 🔑 é');
  });

  it('doubles a backslash, so a text that spells an escape out never passes for one', () => {
    expect(displayText(`spelled \\u{202E} out`, 100)).toBe(`spelled \\\\u{202E} out`);
    expect(displayText(`real ${RLO} one`, 100)).toBe(`real \\u{202E} one`);
  });

  it('shows three combining marks on a character, and escapes any after them', () => {
    const acute = String.fromCodePoint(0x0301);
    expect(displayText(`e${acute}${acute}${acute}`, 100)).toBe(`e${acute}${acute}${acute}`);
    expect(displayText(`e${acute.repeat(5)}x${acute}`, 100)).toBe(
      `e${acute.repeat(3)}\\u{0301}\\u{0301}x${acute}`
    );
  });

  it('caps a string by code points, with an ellipsis, never cutting an escape or a pair', () => {
    expect(displayText('abcdef', 6)).toBe('abcdef');
    expect(displayText('abcdefg', 6)).toBe('abcde…');
    expect(Array.from(displayText('🔑'.repeat(10), 5))).toHaveLength(5);
    expect(displayText('🔑'.repeat(10), 5)).toBe('🔑🔑🔑🔑…');
    // The escape is shown whole or not at all.
    expect(displayText(`abcd${RLO}`, 8)).toBe('abcd…');
    const long = renderOperation(
      { ...APPROVAL, reason: 'x'.repeat(DISPLAY_LIMITS.reason + 1) },
      registryOf(rotate)
    );
    expect(Array.from(long.reason?.text ?? '')).toHaveLength(DISPLAY_LIMITS.reason);
  });

  it('hands the renderer a frozen copy of the stored request, and nothing the requester wrote', () => {
    let seen: RenderInput | undefined;
    renderOperation(
      APPROVAL,
      registryOf((request) => {
        seen = request;
        return { title: 'Rotate' };
      })
    );
    expect(seen).toEqual({
      operationId: 'keys.rotate',
      method: 'POST',
      params: { realmId: 'r', keyId: `signing${RLO}1` },
      query: {},
      body: { comment: `rotate${LRI}now` },
    });
    expect(Object.isFrozen(seen?.params)).toBe(true);
    expect(JSON.stringify(seen)).not.toContain('Please approve');
  });

  it('refuses an operation with no renderer, and a renderer that throws or returns anything else', () => {
    expect(() => renderOperation(APPROVAL, registryOf(undefined))).toThrow(ApprovalRenderError);
    const refused = [
      () => {
        throw new Error('broken');
      },
      () => 'Rotate',
      () => ({ title: '' }),
      () => ({ title: 'Rotate', html: '<b>x</b>' }),
      () => ({ title: 'Rotate', fields: [{ label: 'Key', value: 3 }] }),
      () => ({ title: 'Rotate', fields: [{ label: 'Key', value: 'k', markup: '<i>' }] }),
      () => ({
        title: 'Rotate',
        fields: Array.from({ length: DISPLAY_LIMITS.fields + 1 }, () => ({
          label: 'a',
          value: 'b',
        })),
      }),
    ];
    for (const render of refused) {
      expect(() =>
        renderOperation(APPROVAL, registryOf(render as unknown as AdminOperation['render']))
      ).toThrow(ApprovalRenderError);
    }
  });
});
