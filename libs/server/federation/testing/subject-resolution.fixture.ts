/**
 * TEST SUPPORT — real, fully validated credentials for subject resolution
 * (issue #300).
 *
 * Lives in `testing/` for the same reason `sd-jwt-vc.fixture.ts` does, and this
 * module makes the rule sharper rather than merely inheriting it: it produces
 * `ValidatedCredential` instances by running the ACTUAL validator over an
 * actually-signed presentation. A credential that has passed #234 end to end is
 * the strongest possible input to an authentication-bypass test — "valid in
 * every respect and still must not authenticate this account" is the property
 * ADR-009 §1 is about — and it is exactly the object that must never be
 * constructible from shipped source.
 *
 * Nothing here fakes a `ValidatedIssuer`: the brand comes from the validator, so
 * a test asserting that resolution keys on the VALIDATED issuer is asserting
 * about the real thing.
 */

import { validateSdJwtVcPresentation } from '../src/oid4vp/sd-jwt-vc';
import type { ValidatedCredential } from '../src/oid4vp/validated-credential';
import {
  fixtureValidationContext,
  issueSdJwtVc,
  type IssueSdJwtVcOptions,
  presentSdJwtVc,
  TEST_CREDENTIAL_QUERY,
  TEST_VCT,
} from './sd-jwt-vc.fixture';

/** The claim set a fixture credential discloses unless a test says otherwise. */
export const FIXTURE_SUBJECT_CLAIMS: Readonly<Record<string, unknown>> = Object.freeze({
  given_name: 'Alice',
  family_name: 'Doe',
  birth_date: '1990-01-01',
});

/** What {@link validatedFixtureCredential} may vary. */
export interface ValidatedFixtureOptions {
  /** Selectively disclosable claims the issuer signs. */
  readonly claims?: Record<string, unknown>;
  /** The issuer identity; the resolver is wired to whatever this is. */
  readonly issuer?: string;
  /** The `vct`. Changing it also changes the DCQL query it is matched against. */
  readonly vct?: string;
  /** Anything else `issueSdJwtVc` accepts. */
  readonly issue?: IssueSdJwtVcOptions;
}

/**
 * Issue, present and VALIDATE one credential, returning what #234 produced.
 *
 * @param options - the deviation under test; defaults validate cleanly.
 * @returns a genuine {@link ValidatedCredential}, complete with a branded
 * `ValidatedIssuer`.
 */
export async function validatedFixtureCredential(
  options: ValidatedFixtureOptions = {}
): Promise<ValidatedCredential> {
  const vct = options.vct ?? TEST_VCT;
  const issued = await issueSdJwtVc({
    selectiveClaims: options.claims ?? { ...FIXTURE_SUBJECT_CLAIMS },
    ...(options.issuer === undefined ? {} : { issuer: options.issuer }),
    vct,
    ...(options.issue ?? {}),
  });

  const nonce = `nonce-${Math.random().toString(36).slice(2)}`;
  const presentation = await presentSdJwtVc(issued, { nonce });

  return validateSdJwtVcPresentation(
    presentation,
    TEST_CREDENTIAL_QUERY.id,
    { ...TEST_CREDENTIAL_QUERY, meta: { vct_values: [vct] } },
    fixtureValidationContext(issued, nonce)
  );
}
