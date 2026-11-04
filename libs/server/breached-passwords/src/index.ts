// Breach-list checks of passwords: a local list or a k-anonymity range lookup (#635, ADR-017 Decision 8)
export {
  type ActiveBreachListSource,
  type BreachCheckOutcome,
  type BreachCheckResult,
  type BreachedPasswordChecker,
  type BreachedPasswordCheckerOptions,
  createBreachedPasswordChecker,
} from './lib/checker';
export { passwordSha1 } from './lib/digest';
export {
  BREACH_CHECK_FAILURE_REASONS,
  type BreachCheckFailureReason,
  BreachListError,
  BreachLookupError,
  type BreachLookupFailureReason,
  isBreachLookupError,
} from './lib/errors';
export {
  type BreachListReloadResult,
  createReloadableBreachList,
  loadLocalBreachList,
  type LocalBreachList,
  parseLocalBreachList,
  type ReloadableBreachList,
} from './lib/local-list';
export {
  BREACH_RANGE_LIMITS,
  BREACH_RANGE_PREFIX_LENGTH,
  BREACH_RANGE_PURPOSE,
  type BreachRangeLookup,
  type BreachRangeLookupOptions,
  createBreachRangeLookup,
} from './lib/range-lookup';
