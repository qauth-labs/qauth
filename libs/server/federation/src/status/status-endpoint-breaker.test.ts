import { describe, expect, it } from 'vitest';

import {
  ALWAYS_CLOSED_STATUS_ENDPOINT_BREAKER,
  createStatusEndpointBreaker,
} from './status-endpoint-breaker';

const A = 'https://a.example/lists/1';
const A_OTHER_PATH = 'https://a.example/lists/2';
const B = 'https://b.example/lists/1';

describe('createStatusEndpointBreaker (#297)', () => {
  it('allows requests while the circuit is closed', () => {
    const breaker = createStatusEndpointBreaker({ failureThreshold: 3, now: () => 0 });
    expect(breaker.allows(A)).toBe(true);

    breaker.recordFailure(A);
    breaker.recordFailure(A);
    expect(breaker.allows(A)).toBe(true);
  });

  it('opens after the configured number of consecutive failures', () => {
    const breaker = createStatusEndpointBreaker({ failureThreshold: 3, now: () => 0 });
    breaker.recordFailure(A);
    breaker.recordFailure(A);
    breaker.recordFailure(A);
    expect(breaker.allows(A)).toBe(false);
  });

  it('resets the counter on success', () => {
    const breaker = createStatusEndpointBreaker({ failureThreshold: 3, now: () => 0 });
    breaker.recordFailure(A);
    breaker.recordFailure(A);
    breaker.recordSuccess(A);
    breaker.recordFailure(A);
    breaker.recordFailure(A);
    expect(breaker.allows(A)).toBe(true);
  });

  it('counts by ORIGIN, so varying the path cannot keep the circuit closed', () => {
    const breaker = createStatusEndpointBreaker({ failureThreshold: 2, now: () => 0 });
    breaker.recordFailure(A);
    breaker.recordFailure(A_OTHER_PATH);
    expect(breaker.allows(A)).toBe(false);
    expect(breaker.allows(A_OTHER_PATH)).toBe(false);
  });

  it('isolates origins from one another', () => {
    const breaker = createStatusEndpointBreaker({ failureThreshold: 1, now: () => 0 });
    breaker.recordFailure(A);
    expect(breaker.allows(A)).toBe(false);
    expect(breaker.allows(B)).toBe(true);
  });

  it('stays open for the configured duration, then admits exactly one probe', () => {
    let clock = 0;
    const breaker = createStatusEndpointBreaker({
      failureThreshold: 1,
      openDurationMs: 1_000,
      now: () => clock,
    });

    breaker.recordFailure(A);
    expect(breaker.allows(A)).toBe(false);

    clock = 999;
    expect(breaker.allows(A)).toBe(false);

    clock = 1_000;
    // Half-open: one probe is admitted. A second call before the probe reports
    // back must NOT be, or recovery arrives as a thundering herd.
    expect(breaker.allows(A)).toBe(true);
    expect(breaker.allows(A)).toBe(false);
    expect(breaker.allows(A)).toBe(false);

    breaker.recordFailure(A);
    expect(breaker.allows(A)).toBe(false);
  });

  it('re-arms the open window when a probe never reports back', () => {
    // A probe whose caller crashes (or is cancelled) must not leave the circuit
    // stuck half-open forever, nor stuck closed: the window simply runs again.
    let clock = 0;
    const breaker = createStatusEndpointBreaker({
      failureThreshold: 1,
      openDurationMs: 1_000,
      now: () => clock,
    });

    breaker.recordFailure(A);
    clock = 1_000;
    expect(breaker.allows(A)).toBe(true);

    clock = 1_999;
    expect(breaker.allows(A)).toBe(false);

    clock = 2_000;
    expect(breaker.allows(A)).toBe(true);
  });

  it('closes when the probe succeeds', () => {
    let clock = 0;
    const breaker = createStatusEndpointBreaker({
      failureThreshold: 1,
      openDurationMs: 1_000,
      now: () => clock,
    });

    breaker.recordFailure(A);
    clock = 2_000;
    expect(breaker.allows(A)).toBe(true);
    breaker.recordSuccess(A);
    expect(breaker.allows(A)).toBe(true);
    breaker.recordFailure(A);
    expect(breaker.allows(A)).toBe(false);
  });

  it('refuses an unparseable URI rather than tracking it', () => {
    const breaker = createStatusEndpointBreaker({ now: () => 0 });
    expect(breaker.allows('not a url')).toBe(false);
    // Recording against it must not allocate state either.
    expect(() => breaker.recordFailure('not a url')).not.toThrow();
    expect(() => breaker.recordSuccess('not a url')).not.toThrow();
  });

  it('bounds the number of tracked origins', () => {
    const breaker = createStatusEndpointBreaker({
      failureThreshold: 1,
      maxTrackedOrigins: 2,
      now: () => 0,
    });

    breaker.recordFailure('https://one.example/1');
    breaker.recordFailure('https://two.example/1');
    breaker.recordFailure('https://three.example/1');

    // The oldest origin's state was evicted, so it is admitted again — an
    // acceptable loss of memory, and the reason eviction is bounded at all.
    expect(breaker.allows('https://one.example/1')).toBe(true);
    expect(breaker.allows('https://three.example/1')).toBe(false);
  });

  it.each([
    ['failureThreshold', { failureThreshold: 0 }],
    ['openDurationMs', { openDurationMs: -1 }],
    ['maxTrackedOrigins', { maxTrackedOrigins: 0 }],
  ])('falls back to the default for a nonsensical %s', (_label, options) => {
    const breaker = createStatusEndpointBreaker({ ...options, now: () => 0 });
    breaker.recordFailure(A);
    expect(breaker.allows(A)).toBe(true);
  });
});

describe('ALWAYS_CLOSED_STATUS_ENDPOINT_BREAKER (#297)', () => {
  it('never intervenes', () => {
    ALWAYS_CLOSED_STATUS_ENDPOINT_BREAKER.recordFailure(A);
    ALWAYS_CLOSED_STATUS_ENDPOINT_BREAKER.recordFailure(A);
    expect(ALWAYS_CLOSED_STATUS_ENDPOINT_BREAKER.allows(A)).toBe(true);
  });
});
