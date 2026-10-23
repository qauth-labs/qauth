import { describe, expect, it } from 'vitest';

import {
  ANDROID_GET_LOGIN_CREDS_RELATION,
  buildAppleAppSiteAssociation,
  buildAssetLinks,
} from './app-association';

const FINGERPRINT =
  'FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C';

/** The platform association documents (#467), in the shapes the platforms document. */
describe('buildAppleAppSiteAssociation', () => {
  it('lists the apps under webcredentials, and declares no other service', () => {
    expect(
      buildAppleAppSiteAssociation(['ABCDE12345.com.example.app', 'ABCDE12345.com.example.admin'])
    ).toEqual({
      webcredentials: { apps: ['ABCDE12345.com.example.app', 'ABCDE12345.com.example.admin'] },
    });
  });
});

describe('buildAssetLinks', () => {
  it('writes one get_login_creds statement per app, sorted, and never handle_all_urls', () => {
    const statements = buildAssetLinks({
      'com.example.wallet': [FINGERPRINT],
      'com.example.app': [FINGERPRINT, FINGERPRINT.replace('FA', 'FB')],
    });

    expect(statements).toEqual([
      {
        relation: [ANDROID_GET_LOGIN_CREDS_RELATION],
        target: {
          namespace: 'android_app',
          package_name: 'com.example.app',
          sha256_cert_fingerprints: [FINGERPRINT, FINGERPRINT.replace('FA', 'FB')],
        },
      },
      {
        relation: ['delegate_permission/common.get_login_creds'],
        target: {
          namespace: 'android_app',
          package_name: 'com.example.wallet',
          sha256_cert_fingerprints: [FINGERPRINT],
        },
      },
    ]);
    expect(JSON.stringify(statements)).not.toContain('handle_all_urls');
  });
});
