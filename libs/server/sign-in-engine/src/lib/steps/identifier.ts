import { readIdentifier } from '../identifier';
import type { StepHandler } from './handler';

/**
 * The identifier step (ADR-017 Decision 3: `urn:qauth:ia:identifier`, answer
 * `login_hint`). Offered with no params and no personal data, the same for
 * everyone; its answer reads no account. The engine takes the identifier
 * from the authorization request's `login_hint`, or from the `login_hint` of
 * an answer (this step's, or a password answer's when the page asks for both
 * at once), and fixes the first one for the transaction.
 */
export function createIdentifierStep(): StepHandler<'identifier'> {
  const handler: StepHandler<'identifier'> = {
    step: 'identifier',
    role: 'identifier',
    params: () => ({}),
    personal: () => ({}),
    async verify(_round, read) {
      const identifier = readIdentifier(read.answer.login_hint);
      // The engine reads every `login_hint` with the same check before it
      // asks a handler, so a refusal here is a fault of the engine.
      if (identifier === null) throw new Error('identifier step: an unread login_hint');
      return { kind: 'identified', identifier };
    },
  };
  return Object.freeze(handler);
}
