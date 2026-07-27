import { InvalidConfigurationError, InvalidCredentialsError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { ISSUER_TRUST_REJECTION_MESSAGE } from '../trust/issuer-trust-rejection';
import type { SubjectResolutionOutcome } from './subject-resolution.types';
import {
  assertSubjectResolutionStrategySelectable,
  assertSubjectResolved,
  createSubjectResolutionStrategy,
  parseSubjectResolutionStrategyId,
  SUBJECT_RESOLUTION_STRATEGIES,
  SUBJECT_RESOLUTION_STRATEGY_IDS,
  type SubjectResolutionStrategyDescriptor,
} from './subject-resolution-strategies';

/**
 * The strategy table, its gates, and the single refusal (#300, ADR-009).
 */

describe('SUBJECT_RESOLUTION_STRATEGIES (issue #300)', () => {
  describe('table invariants — hold for every strategy, including future ones', () => {
    it.each(SUBJECT_RESOLUTION_STRATEGY_IDS)("'%s' carries an id matching its table key", (id) => {
      expect(SUBJECT_RESOLUTION_STRATEGIES[id].id).toBe(id);
    });

    it.each(SUBJECT_RESOLUTION_STRATEGY_IDS)("'%s' is frozen against mutation at runtime", (id) => {
      // The table is shared, long-lived config. A request handler flipping a
      // `usage` would permanently open a gate process-wide.
      expect(Object.isFrozen(SUBJECT_RESOLUTION_STRATEGIES[id])).toBe(true);
      expect(() => {
        (SUBJECT_RESOLUTION_STRATEGIES[id] as { usage: string }).usage = 'login';
      }).toThrow();
    });

    it('is itself frozen, so a strategy cannot be added or replaced at runtime', () => {
      expect(Object.isFrozen(SUBJECT_RESOLUTION_STRATEGIES)).toBe(true);
    });

    it('derives SUBJECT_RESOLUTION_STRATEGY_IDS from the table rather than restating it', () => {
      expect([...SUBJECT_RESOLUTION_STRATEGY_IDS].sort()).toEqual(
        Object.keys(SUBJECT_RESOLUTION_STRATEGIES).sort()
      );
    });

    it.each(SUBJECT_RESOLUTION_STRATEGY_IDS)(
      "'%s' carries a refusal exactly when it is not selectable",
      (id) => {
        // A gated strategy whose refusal said nothing would be indistinguishable
        // from a typo, which is the entire failure this table exists to avoid.
        //
        // Read through the DECLARED interface, not the `satisfies` literal type:
        // the point is what a caller holding a descriptor sees, and the literal
        // type of a `login` row has no `refusal` property to inspect at all.
        const descriptor: SubjectResolutionStrategyDescriptor = SUBJECT_RESOLUTION_STRATEGIES[id];

        if (descriptor.usage === 'login') {
          expect(descriptor.refusal).toBeUndefined();
          return;
        }

        expect(descriptor.refusal ?? '').not.toBe('');
      }
    );

    it('reserves every strategy ADR-009 names, implemented or not', () => {
      // ADR-009 §3: "Recording it now is the point. When the gates clear, the
      // correct move is to add a strategy — not to rediscover the problem and
      // invent a private identifier."
      expect([...SUBJECT_RESOLUTION_STRATEGY_IDS].sort()).toEqual([
        'asserted-lookup',
        'issuer-scoped-claim',
        'key-thumbprint',
        'rp-pseudonym',
        'session-binding',
      ]);
    });
  });

  describe('parseSubjectResolutionStrategyId — fail-CLOSED, like parseVerifierProfileId', () => {
    it.each(SUBJECT_RESOLUTION_STRATEGY_IDS)("accepts the known id '%s'", (id) => {
      expect(parseSubjectResolutionStrategyId(id)).toBe(id);
    });

    it.each([null, undefined, '', 'asserted_lookup', 'Asserted-Lookup', 'lookup', 'production'])(
      'discards %o rather than coercing it to the default',
      (raw) => {
        // A realm meant to run `issuer-scoped-claim` with a typo'd value must
        // not silently run `asserted-lookup` against a binding claim set chosen
        // for a different ecosystem.
        expect(parseSubjectResolutionStrategyId(raw)).toBeUndefined();
      }
    );
  });

  describe('assertSubjectResolutionStrategySelectable — the gates', () => {
    it.each(['asserted-lookup', 'issuer-scoped-claim'] as const)('permits %s', (id) => {
      expect(() => assertSubjectResolutionStrategySelectable(id)).not.toThrow();
    });

    it('refuses session-binding as a deployment-wide login strategy (ADR-009 §5)', () => {
      // It answers "link", not "log in"; a deployment configured this way would
      // have a login flow that authenticates only users already authenticated.
      expect(() => assertSubjectResolutionStrategySelectable('session-binding')).toThrow(
        InvalidConfigurationError
      );
      expect(() => assertSubjectResolutionStrategySelectable('session-binding')).toThrow(
        /ADR-009 §5/
      );
    });

    it('refuses key-thumbprint and explains why it is not merely fragile (ADR-009 §4)', () => {
      expect(() => assertSubjectResolutionStrategySelectable('key-thumbprint')).toThrow(
        InvalidConfigurationError
      );
      expect(() => assertSubjectResolutionStrategySelectable('key-thumbprint')).toThrow(
        /ADR-009 §4/
      );
    });

    it('refuses rp-pseudonym and states the gates (ADR-009 §3)', () => {
      // Including the one that must not clear vacuously: "Treat 'the gate
      // cleared' as requiring a published specification, not merely the
      // disappearance of the requirement to write one."
      expect(() => assertSubjectResolutionStrategySelectable('rp-pseudonym')).toThrow(
        InvalidConfigurationError
      );
      expect(() => assertSubjectResolutionStrategySelectable('rp-pseudonym')).toThrow(/PUBLISHED/);
    });
  });

  describe('createSubjectResolutionStrategy — the one construction point', () => {
    it('builds asserted-lookup', () => {
      const strategy = createSubjectResolutionStrategy({
        strategy: 'asserted-lookup',
        bindingClaims: ['given_name'],
      });

      expect(strategy.id).toBe('asserted-lookup');
    });

    it('builds issuer-scoped-claim', () => {
      const strategy = createSubjectResolutionStrategy({
        strategy: 'issuer-scoped-claim',
        subjectClaim: 'employee_number',
        issuers: ['https://hr.example.com'],
        fallback: { bindingClaims: ['given_name'] },
      });

      expect(strategy.id).toBe('issuer-scoped-claim');
    });

    it.each([
      ['a linking strategy', 'session-binding'],
      ['a gated strategy', 'rp-pseudonym'],
      ['an unknown strategy', 'invented-here'],
      ['nothing at all', undefined],
    ])('refuses to build %s', (_label, strategy) => {
      expect(() => createSubjectResolutionStrategy({ strategy } as never)).toThrow(
        InvalidConfigurationError
      );
    });
  });

  describe('assertSubjectResolved — one refusal, so nothing is enumerable', () => {
    it('returns the resolved user id', () => {
      expect(assertSubjectResolved({ kind: 'matched', userId: 'user-1' })).toBe('user-1');
    });

    const refusals: readonly SubjectResolutionOutcome[] = [
      { kind: 'no-match' },
      { kind: 'ambiguous' },
      { kind: 'rejected' },
      { kind: 'matched', userId: '' },
    ];

    it('raises the IDENTICAL error for a failed lookup and a failed proof', () => {
      // #300 constraint 4, and the acceptance criterion "Failed lookup and
      // failed proof are externally indistinguishable". Asserted on the shape a
      // client can actually observe — class, status, code and message — because
      // that is what an attacker compares.
      const observed = refusals.map((outcome) => {
        try {
          assertSubjectResolved(outcome);
          return null;
        } catch (error) {
          const domain = error as InvalidCredentialsError;
          return {
            name: domain.constructor.name,
            statusCode: domain.statusCode,
            code: domain.code,
            message: domain.message,
          };
        }
      });

      expect(observed.every((entry) => entry !== null)).toBe(true);
      expect(new Set(observed.map((entry) => JSON.stringify(entry))).size).toBe(1);
      expect(observed[0]?.message).toBe(ISSUER_TRUST_REJECTION_MESSAGE);
    });

    it('reuses the wallet path’s existing refusal rather than minting a second one', () => {
      // #236 already established that an untrusted issuer and a malformed
      // presentation must be indistinguishable. A distinct subject-resolution
      // error would let a caller tell "credential rejected" from "no such
      // account" at the seam between the two layers.
      expect(() => assertSubjectResolved({ kind: 'rejected' })).toThrow(InvalidCredentialsError);
      expect(() => assertSubjectResolved({ kind: 'rejected' })).toThrow(
        ISSUER_TRUST_REJECTION_MESSAGE
      );
    });

    it('refuses a malformed outcome rather than trusting its shape', () => {
      expect(() => assertSubjectResolved(undefined as never)).toThrow(InvalidCredentialsError);
      expect(() =>
        assertSubjectResolved({ kind: 'matched', userId: 7 } as unknown as SubjectResolutionOutcome)
      ).toThrow(InvalidCredentialsError);
    });
  });
});
