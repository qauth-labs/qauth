import { describe, expect, it } from 'vitest';

import { deviceLabelOf, UNKNOWN_DEVICE_LABEL } from './device-label';

/** User agents as the browsers send them, with the label each gets. */
const USER_AGENTS: readonly (readonly [string, string])[] = [
  ['Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0', 'Firefox on Linux'],
  [
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    'Safari on iPhone',
  ],
  [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
    'Safari on macOS',
  ],
  [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Chrome on Windows',
  ],
  [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    'Edge on Windows',
  ],
  [
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
    'Chrome on Android',
  ],
  [
    'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
    'Samsung Internet on Android',
  ],
  [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/115.0.0.0',
    'Opera on macOS',
  ],
  [
    'Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1',
    'Chrome on iPad',
  ],
  [
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/133.0 Mobile/15E148 Safari/605.1.15',
    'Firefox on iPhone',
  ],
  [
    'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Chrome on ChromeOS',
  ],
];

describe('deviceLabelOf (#1110)', () => {
  it.each(USER_AGENTS)('labels %s as %s', (userAgent, label) => {
    expect(deviceLabelOf(userAgent)).toBe(label);
  });

  it('names the browser or the system alone when only one is recognised', () => {
    expect(deviceLabelOf('Mozilla/5.0 Firefox/133.0')).toBe('Firefox');
    expect(deviceLabelOf('curl/8.5.0 (Linux)')).toBe('Linux');
  });

  it('is the unknown device for no header, an empty one, or one it recognises nothing in', () => {
    for (const userAgent of [null, undefined, '', 'curl/8.5.0', 'Browser/1']) {
      expect(deviceLabelOf(userAgent)).toBe(UNKNOWN_DEVICE_LABEL);
    }
  });

  it('never repeats the header’s own text: markup and control characters stay out', () => {
    const label = deviceLabelOf('<script>alert(1)</script>\u0000 Firefox/1 (Windows) ‮');
    expect(label).toBe('Firefox on Windows');
    expect(deviceLabelOf('<img src=x onerror=alert(1)>')).toBe(UNKNOWN_DEVICE_LABEL);
  });

  it('reads at most the length a session stores', () => {
    expect(deviceLabelOf(`${'x'.repeat(1024)} Firefox/1`)).toBe(UNKNOWN_DEVICE_LABEL);
  });
});
