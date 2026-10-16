/**
 * zxcvbn's matcher module. It is not part of zxcvbn's documented API and
 * `@types/zxcvbn` does not declare it; only what `password.ts` and its tests
 * touch is declared here.
 */
declare module 'zxcvbn/lib/matching' {
  /** Letter → characters that may stand for it (the shape of zxcvbn's L33T_TABLE). */
  type L33tTable = Record<string, string[]>;
  /** One substitution map: l33t character → the letter it stands for. */
  type L33tSubstitution = Record<string, string>;

  const matching: {
    enumerate_l33t_subs(this: unknown, table: L33tTable): L33tSubstitution[];
    dictionary_match(this: unknown, password: string, rankedDictionaries?: unknown): unknown[];
  };

  export default matching;
}
