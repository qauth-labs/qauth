import { describe, expect, it } from 'vitest';

import { isLoopbackHost, redirectTarget } from './redirect-target';

describe('redirectTarget (#593)', () => {
  it('returns a web host in its ASCII form, without a trailing dot', () => {
    expect(redirectTarget('https://App.Example.com/cb')).toEqual({
      target: 'host',
      host: 'app.example.com',
    });
    expect(redirectTarget('https://bücher.example./cb')).toEqual({
      target: 'host',
      host: 'xn--bcher-kva.example',
    });
    expect(redirectTarget('https://192.0.2.10:8443/cb')).toEqual({
      target: 'host',
      host: '192.0.2.10',
    });
  });

  it('returns a loopback address as this device', () => {
    for (const uri of [
      'http://127.0.0.1:53817/cb',
      'http://[::1]/cb',
      'http://localhost/cb',
      'https://dev.localhost/cb',
    ]) {
      expect(redirectTarget(uri), uri).toEqual({ target: 'this_device' });
    }
  });

  it('returns a native app by its scheme, up to 64 characters', () => {
    expect(redirectTarget('com.example.notes:/callback')).toEqual({
      target: 'app',
      scheme: 'com.example.notes',
    });
    expect(redirectTarget(`com.example.${'a'.repeat(52)}:/cb`)?.target).toBe('app');
    expect(redirectTarget(`com.example.${'a'.repeat(53)}:/cb`)).toBeUndefined();
  });

  it('returns nothing for what the contract cannot carry', () => {
    for (const uri of [
      'not a url',
      'https://[2001:db8::1]/cb',
      'https://my_app.example.com/cb',
      'https://a..b.example/cb',
      'https://-app.example.com/cb',
      `https://${'a'.repeat(64)}.example/cb`,
    ]) {
      expect(redirectTarget(uri), uri).toBeUndefined();
    }
  });

  it('tells loopback hosts apart from look-alikes', () => {
    expect(isLoopbackHost('127.255.255.254')).toBe(true);
    expect(isLoopbackHost('[::ffff:7f00:1]')).toBe(true);
    expect(isLoopbackHost('0.0.0.0')).toBe(true);
    expect(isLoopbackHost('128.0.0.1')).toBe(false);
    expect(isLoopbackHost('localhost.example.com')).toBe(false);
    expect(isLoopbackHost('[::ffff:c000:201]')).toBe(false);
  });
});
