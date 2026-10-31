import { join } from 'node:path';

import ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * The acceptance criterion: the step union is exhaustive, so a step added to
 * the grammar without a mapper fails the type check. Vitest does not type
 * check, so this test runs the TypeScript compiler itself, with the library's
 * own compiler options, over samples that add a step `sample` to the union
 * and hand the real mapper tables to the extended table types. A sample with
 * the missing entries added must compile, so the failures are the missing
 * mappers' and nothing else.
 */

const HEADER = `
import { z } from 'zod';
import { FIPA_STEP_MAPPERS, type FipaMapperTable, INTERACTION_ONLY } from './fipa-mapper';
import { defineStep } from './grammar';
import { INTERACTION_STEP_MAPPERS, type InteractionMapperTable } from './interaction-mapper';
import type { GrammarStepUnion } from './steps';

const fipaStep = defineStep({
  name: 'sample',
  transports: ['interaction', 'fipa'],
  params: z.strictObject({ size: z.int().min(1).max(9) }),
  personal: z.strictObject({}),
  answer: z.strictObject({}),
  errors: [],
  amr: [],
});
const interactionOnlyStep = defineStep({ ...fipaStep, transports: ['interaction'] });
type WithFipaStep = GrammarStepUnion | typeof fipaStep;
type WithInteractionOnlyStep = GrammarStepUnion | typeof interactionOnlyStep;
void INTERACTION_ONLY;
`;

const SAMPLES = {
  complete: `
export const interaction: InteractionMapperTable<WithFipaStep> = { ...INTERACTION_STEP_MAPPERS, sample: (params) => params };
export const fipa: FipaMapperTable<WithFipaStep> = { ...FIPA_STEP_MAPPERS, sample: (params) => params };
export const fipaMarked: FipaMapperTable<WithInteractionOnlyStep> = { ...FIPA_STEP_MAPPERS, sample: INTERACTION_ONLY };
`,
  noInteractionMapper: `
export const interaction: InteractionMapperTable<WithFipaStep> = INTERACTION_STEP_MAPPERS;
`,
  noFipaMapper: `
export const fipa: FipaMapperTable<WithFipaStep> = FIPA_STEP_MAPPERS;
`,
  noFipaMarker: `
export const fipa: FipaMapperTable<WithInteractionOnlyStep> = FIPA_STEP_MAPPERS;
`,
  fipaMapperForInteractionOnlyStep: `
export const fipa: FipaMapperTable<WithInteractionOnlyStep> = { ...FIPA_STEP_MAPPERS, sample: (params: { size: number }) => params };
`,
  fipaStepMarkedInteractionOnly: `
export const fipa: FipaMapperTable<WithFipaStep> = { ...FIPA_STEP_MAPPERS, sample: INTERACTION_ONLY };
`,
  mapperOfTheWrongType: `
export const interaction: InteractionMapperTable<WithFipaStep> = { ...INTERACTION_STEP_MAPPERS, sample: () => ({ size: 'large' }) };
`,
} as const;

type Sample = keyof typeof SAMPLES;

const fileOf = (sample: Sample) => join(__dirname, `exhaustive-sample-${sample}.ts`);

/** The error diagnostics of every sample, from one program. */
function compileSamples(): Record<Sample, string[]> {
  const configPath = join(__dirname, '..', '..', 'tsconfig.lib.json');
  const config = ts.getParsedCommandLineOfConfigFile(
    configPath,
    {},
    {
      ...ts.sys,
      onUnRecoverableConfigFileDiagnostic: (diagnostic) => {
        throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'));
      },
    }
  );
  if (config === undefined) throw new Error(`cannot read ${configPath}`);
  const options: ts.CompilerOptions = {
    ...config.options,
    noEmit: true,
    composite: false,
    declaration: false,
    incremental: false,
    tsBuildInfoFile: undefined,
  };
  const sources = new Map(
    (Object.keys(SAMPLES) as Sample[]).map((sample) => [fileOf(sample), HEADER + SAMPLES[sample]])
  );
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, ...rest) => {
    const source = sources.get(fileName);
    return source === undefined
      ? getSourceFile(fileName, languageVersion, ...rest)
      : ts.createSourceFile(fileName, source, languageVersion, true);
  };
  host.fileExists = (fileName) => sources.has(fileName) || ts.sys.fileExists(fileName);
  host.readFile = (fileName) => sources.get(fileName) ?? ts.sys.readFile(fileName);
  const program = ts.createProgram({ rootNames: [...sources.keys()], options, host });
  return Object.fromEntries(
    (Object.keys(SAMPLES) as Sample[]).map((sample) => [
      sample,
      ts
        .getPreEmitDiagnostics(program, program.getSourceFile(fileOf(sample)))
        .filter((diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error)
        .map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n')),
    ])
  ) as Record<Sample, string[]>;
}

describe('the mapper tables', () => {
  let errors: Record<Sample, string[]>;
  beforeAll(() => {
    errors = compileSamples();
  }, 120_000);

  it('compile with a new step once each transport has its entry', () => {
    expect(errors.complete).toEqual([]);
  });

  it('fail the type check for a new step without an Interaction API mapper', () => {
    expect(errors.noInteractionMapper.join('\n')).toMatch(/Property 'sample' is missing/);
  });

  it('fail the type check for a new step without a FiPA entry, whether a mapper or the Interaction-only marker', () => {
    expect(errors.noFipaMapper.join('\n')).toMatch(/Property 'sample' is missing/);
    expect(errors.noFipaMarker.join('\n')).toMatch(/Property 'sample' is missing/);
  });

  it('fail the type check for a FiPA mapper of a step only the Interaction API serves, and for the marker on a FiPA step', () => {
    expect(errors.fipaMapperForInteractionOnlyStep.join('\n')).toMatch(
      /is not assignable to type 'unique symbol'/
    );
    expect(errors.fipaStepMarkedInteractionOnly.join('\n')).toMatch(
      /^Type 'symbol' is not assignable to type 'FipaStepMapper<GrammarStep<"sample"/
    );
  });

  it('fail the type check for a mapper that returns params of another shape', () => {
    expect(errors.mapperOfTheWrongType.join('\n')).toMatch(
      /Type 'string' is not assignable to type 'number'/
    );
  });
});
