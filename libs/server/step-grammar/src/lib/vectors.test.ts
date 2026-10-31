import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { strictValidator } from '@qauth-labs/shared-interaction-contract/src/testing/schema-validator';
import { loadVectors } from '@qauth-labs/shared-test-vectors';
import { describe, expect, it } from 'vitest';

import { readPublishedStepFile, REPO_ROOT } from '../testing/published-files';
import { STEP_NAMES, type StepName, stepNameOfUrn } from './steps';
import {
  STEP_VECTORS_ID,
  STEP_VECTORS_PATH,
  type StepVectorExpected,
  stepVectorExpected,
  stepVectorFile,
  type StepVectorInput,
  VECTORS_EXPORT_COMMAND,
} from './vectors';

// The id as a literal: shared-test-vectors' tree test finds a file's loader by it.
const vectors = loadVectors<StepVectorInput, StepVectorExpected>('interaction/steps');

describe('the step vectors (test-vectors/interaction/steps.json)', () => {
  it('are what the contract’s examples and the mappers give', () => {
    const committed: unknown = JSON.parse(readFileSync(join(REPO_ROOT, STEP_VECTORS_PATH), 'utf8'));
    expect(
      committed,
      `run \`${VECTORS_EXPORT_COMMAND.replace(' --skip-nx-cache', '')}\` and commit the result. Until QAuth 1.0.0 the file follows the contract's release candidate and is replaced whole (test-vectors/README.md); from 1.0.0 on its cases are fixed.`
    ).toStrictEqual(JSON.parse(JSON.stringify(stepVectorFile())));
  });

  it('hold one case per step, in grammar order', () => {
    expect(vectors.id).toBe(STEP_VECTORS_ID);
    expect(vectors.cases.map((vector) => stepNameOfUrn(vector.input.step.type))).toEqual(
      STEP_NAMES
    );
  });

  // The server's side: the mappers compute every case's expected result.
  it.each(vectors.cases.map((vector) => [vector.id, vector] as const))(
    '%s: the mappers give the expected result',
    (_id, vector) => {
      expect(JSON.parse(JSON.stringify(stepVectorExpected(vector.input)))).toStrictEqual(
        vector.expected
      );
    }
  );

  // A client's side: an SDK reads the response and recovers the step.
  it.each(vectors.cases.map((vector) => [vector.id, vector] as const))(
    '%s: a reader recovers the step, its params and its error from each transport’s answer',
    (_id, vector) => {
      const { step } = vector.input;
      const view = vector.expected.interaction as {
        step: string;
        error?: string;
        params: Record<string, unknown>;
      };
      expect(view.step).toBe(step.type);
      expect(view.params[view.step]).toEqual(step.params);
      expect(view.error).toBe(step.error);
      const body = vector.expected.fipa.body as Record<string, unknown>;
      expect(vector.expected.fipa.status).toBe(403);
      if (body['error'] === 'redirect_to_web') {
        expect(Object.keys(body).sort()).toEqual(['error', 'iss']);
        return;
      }
      expect(body['interaction_type_required']).toBe(step.type);
      expect((body['qauth_interaction_params'] as Record<string, unknown>)[step.type]).toEqual(
        step.params
      );
      expect(body['qauth_interaction_error']).toBe(step.error);
    }
  );

  // The record is the step's own example, so a reader can validate it with the
  // step's published schema file and any JSON Schema 2020-12 validator.
  it.each(vectors.cases.map((vector) => [vector.id, vector] as const))(
    '%s: the step record validates against the step’s published schema',
    (_id, vector) => {
      const name = stepNameOfUrn(vector.input.step.type) as StepName;
      const file = readPublishedStepFile(name) as { examples: unknown[] };
      expect(file.examples[0]).toStrictEqual(vector.input.step);
      const ajv = strictValidator();
      expect(ajv.validate(file, vector.input.step)).toBe(true);
      const listed = vector.input.fipa.interaction_types_supported;
      expect(listed.length).toBeLessThanOrEqual(16);
      for (const urn of [vector.input.step.type, ...vector.input.alternatives.map((a) => a.type)]) {
        expect(listed).toContain(urn);
      }
    }
  );
});
