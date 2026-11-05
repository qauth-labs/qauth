/**
 * The errors of the AuthMethod contract (#599). None of them reaches the wire
 * with its details: they name a fault of a method's code or of its config,
 * for the operator's log. A request that meets one answers with the generic
 * error page and its trace id.
 *
 * @experimental
 */

/**
 * A method does not meet the contract: thrown when it is registered (the boot
 * fails) and by the contract test kit. `problems` lists every problem found,
 * one sentence each.
 *
 * @experimental
 */
export class AuthMethodContractError extends Error {
  /** Every problem found, one sentence each. */
  readonly problems: readonly string[];

  constructor(subject: string, problems: readonly string[]) {
    super(`${subject} does not meet the AuthMethod contract:\n- ${problems.join('\n- ')}`);
    this.name = 'AuthMethodContractError';
    this.problems = Object.freeze([...problems]);
    Object.setPrototypeOf(this, AuthMethodContractError.prototype);
  }
}

/**
 * A method broke the contract at run time: `start()` answered something the
 * engine cannot use, a callback handed back an outcome outside the closed set,
 * or `verify()`/`extractAttributes()` produced an identity or attributes the
 * engine refuses. The engine never acts on such an answer.
 *
 * @experimental
 */
export class AuthMethodFaultError extends Error {
  /** The method's `type`. */
  readonly methodType: string;

  constructor(methodType: string, problem: string, options?: { cause?: unknown }) {
    super(`AuthMethod ${methodType}: ${problem}`, options);
    this.name = 'AuthMethodFaultError';
    this.methodType = methodType;
    Object.setPrototypeOf(this, AuthMethodFaultError.prototype);
  }
}

/**
 * A realm's stored config of a method does not pass the method's
 * `configSchema`. `issues` names the members, never their values, since a
 * member may be a secret.
 *
 * @experimental
 */
export class AuthMethodConfigError extends Error {
  /** The method's `type`. */
  readonly methodType: string;
  /** Each failing member's path and the schema's code, never its value. */
  readonly issues: readonly string[];

  constructor(methodType: string, issues: readonly string[]) {
    super(`AuthMethod ${methodType}: the config does not pass the method's schema`);
    this.name = 'AuthMethodConfigError';
    this.methodType = methodType;
    this.issues = Object.freeze([...issues]);
    Object.setPrototypeOf(this, AuthMethodConfigError.prototype);
  }
}
