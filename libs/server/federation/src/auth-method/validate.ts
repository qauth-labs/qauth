import type { CredentialProvider } from '../providers/credential-provider.interface';
import type { AuthMethod } from './auth-method.interface';
import {
  AUTH_METHOD_CONTRACT,
  AUTH_METHOD_CONTRACT_NAME,
  AUTH_METHOD_DISPLAY_NAME_PATTERN,
  AUTH_METHOD_ICON_MEDIA_TYPES,
  AUTH_METHOD_ID_PATTERN,
  AUTH_METHOD_ROUTE_PATH_PATTERN,
  AUTH_METHOD_STEP_URNS,
  AUTH_METHOD_TYPE_PATTERN,
  MAX_AUTH_METHOD_DISPLAY_NAME_LENGTH,
  MAX_AUTH_METHOD_ICON_BYTES,
  RESERVED_AUTH_METHOD_TYPES,
} from './contract';
import { AuthMethodContractError } from './errors';

/**
 * The static checks of the AuthMethod contract (#599): what a method must be
 * before the registry accepts it. The registry runs them at registration, so a
 * method that fails one fails the boot. The contract test kit runs them too,
 * then exercises the method.
 *
 * @experimental
 */

/** The eight bytes every PNG file starts with. */
const PNG_SIGNATURE = Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);

/**
 * Whether `provider` presents itself as an AuthMethod: it has a `contract`
 * member. A plain `CredentialProvider` has none. The registry then holds it to
 * the whole contract ({@link assertAuthMethod}), so a provider cannot carry a
 * `contract` member and skip the checks.
 *
 * @experimental
 */
export function declaresAuthMethodContract(provider: CredentialProvider): boolean {
  return 'contract' in provider;
}

/**
 * Whether `value` meets the static checks of the contract.
 *
 * @experimental
 */
export function isAuthMethod(value: unknown): value is AuthMethod {
  return authMethodProblems(value).length === 0;
}

/**
 * Throw an {@link AuthMethodContractError} listing every problem when `value`
 * does not meet the static checks of the contract.
 *
 * @experimental
 */
export function assertAuthMethod(value: unknown): asserts value is AuthMethod {
  const problems = authMethodProblems(value);
  if (problems.length > 0) {
    throw new AuthMethodContractError(describeMethod(value), problems);
  }
}

/**
 * Every static problem of `value` as an AuthMethod, one sentence each; empty
 * when there is none.
 *
 * @experimental
 */
export function authMethodProblems(value: unknown): string[] {
  if (typeof value !== 'object' || value === null) return ['it is not an object'];
  const method = value as Record<string, unknown>;
  const problems: string[] = [];

  problems.push(...contractProblems(method['contract']));
  problems.push(...authMethodTypeProblems(method['type']));

  if (typeof method['id'] !== 'string' || !AUTH_METHOD_ID_PATTERN.test(method['id'])) {
    problems.push(`id must match ${AUTH_METHOD_ID_PATTERN.source}`);
  }

  for (const member of ['verify', 'extractAttributes', 'start']) {
    if (typeof method[member] !== 'function') problems.push(`${member} must be a function`);
  }

  problems.push(...displayProblems(method['display']));

  const schema = method['configSchema'];
  if (
    typeof schema !== 'object' ||
    schema === null ||
    typeof (schema as Record<string, unknown>)['safeParse'] !== 'function'
  ) {
    problems.push('configSchema must be a Zod schema');
  }

  problems.push(...stepProblems(method['steps']));
  problems.push(...routeProblems(method['routes']));
  return problems;
}

/**
 * The problems of a route list; exported for the mount, which checks again.
 *
 * @experimental
 */
export function routeProblems(routes: unknown): string[] {
  if (!Array.isArray(routes)) return ['routes must be a list'];
  const problems: string[] = [];
  const seen = new Set<string>();
  let callbacks = 0;

  routes.forEach((route: unknown, index) => {
    const at = `routes[${index}]`;
    if (typeof route !== 'object' || route === null) {
      problems.push(`${at} must be an object`);
      return;
    }
    const entry = route as Record<string, unknown>;
    if (entry['kind'] !== 'callback' && entry['kind'] !== 'bounce') {
      problems.push(`${at}.kind must be callback or bounce`);
    }
    if (entry['kind'] === 'callback') callbacks += 1;
    if (entry['method'] !== 'GET' && entry['method'] !== 'POST') {
      problems.push(`${at}.method must be GET or POST`);
    }
    const path = entry['path'];
    if (typeof path !== 'string' || !AUTH_METHOD_ROUTE_PATH_PATTERN.test(path)) {
      problems.push(
        `${at}.path must be one to four lower-case segments, such as /callback: a route cannot leave the method's prefix`
      );
    } else {
      const key = `${String(entry['method'])} ${path}`;
      if (seen.has(key)) problems.push(`${at} repeats ${key}`);
      seen.add(key);
    }
    if (typeof entry['handle'] !== 'function') problems.push(`${at}.handle must be a function`);
  });

  if (callbacks === 0) {
    problems.push('routes must hold at least one callback route: the upstream step returns there');
  }
  return problems;
}

function contractProblems(contract: unknown): string[] {
  if (contract === AUTH_METHOD_CONTRACT) return [];
  if (typeof contract === 'string' && contract.startsWith(`${AUTH_METHOD_CONTRACT_NAME}/`)) {
    return [
      `it is written against the contract ${contract}, and this server implements ${AUTH_METHOD_CONTRACT}`,
    ];
  }
  return [`contract must be ${AUTH_METHOD_CONTRACT}`];
}

/**
 * The problems of `type` as an AuthMethod's type: its pattern, and not one of
 * the reserved types.
 *
 * @experimental
 */
export function authMethodTypeProblems(type: unknown): string[] {
  if (typeof type !== 'string' || !AUTH_METHOD_TYPE_PATTERN.test(type)) {
    return [`type must match ${AUTH_METHOD_TYPE_PATTERN.source}`];
  }
  if (RESERVED_AUTH_METHOD_TYPES.includes(type)) {
    return [`type ${type} is reserved for QAuth's own credentials`];
  }
  return [];
}

function displayProblems(display: unknown): string[] {
  if (typeof display !== 'object' || display === null) return ['display must be an object'];
  const { name, icon } = display as Record<string, unknown>;
  const problems: string[] = [];
  if (
    typeof name !== 'string' ||
    name.length > MAX_AUTH_METHOD_DISPLAY_NAME_LENGTH ||
    !AUTH_METHOD_DISPLAY_NAME_PATTERN.test(name)
  ) {
    problems.push(
      `display.name must be at most ${MAX_AUTH_METHOD_DISPLAY_NAME_LENGTH} characters under the display rule: no markup bracket, no control or invisible character, no space at either end`
    );
  }
  if (icon !== undefined) problems.push(...iconProblems(icon));
  return problems;
}

function iconProblems(icon: unknown): string[] {
  if (typeof icon !== 'object' || icon === null) return ['display.icon must be an object'];
  const { mediaType, bytes } = icon as Record<string, unknown>;
  const problems: string[] = [];
  if (!(AUTH_METHOD_ICON_MEDIA_TYPES as readonly unknown[]).includes(mediaType)) {
    problems.push(`display.icon.mediaType must be ${AUTH_METHOD_ICON_MEDIA_TYPES.join(' or ')}`);
  }
  if (!(bytes instanceof Uint8Array)) {
    problems.push('display.icon.bytes must be a Uint8Array');
  } else if (bytes.byteLength > MAX_AUTH_METHOD_ICON_BYTES) {
    problems.push(`display.icon.bytes must be at most ${MAX_AUTH_METHOD_ICON_BYTES} bytes`);
  } else if (!PNG_SIGNATURE.every((byte, index) => bytes[index] === byte)) {
    problems.push('display.icon.bytes must be a PNG file');
  }
  return problems;
}

function stepProblems(steps: unknown): string[] {
  if (!Array.isArray(steps) || steps.length === 0) {
    return ['steps must list at least one step'];
  }
  const problems: string[] = [];
  const seen = new Set<unknown>();
  for (const step of steps) {
    if (seen.has(step)) problems.push(`steps repeats ${String(step)}`);
    seen.add(step);
    if ((AUTH_METHOD_STEP_URNS as readonly unknown[]).includes(step)) continue;
    problems.push(
      `steps holds ${String(step)}, which is not a step a method may contribute here (${AUTH_METHOD_STEP_URNS.join(', ')})`
    );
  }
  return problems;
}

/** How a candidate is named in an error: its type, when it has a usable one. */
function describeMethod(value: unknown): string {
  if (typeof value === 'object' && value !== null) {
    const type = (value as Record<string, unknown>)['type'];
    if (typeof type === 'string' && AUTH_METHOD_TYPE_PATTERN.test(type)) {
      return `The AuthMethod ${type}`;
    }
  }
  return 'An AuthMethod';
}
