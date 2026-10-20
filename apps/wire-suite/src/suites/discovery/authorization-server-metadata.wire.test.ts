import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { getJsonObject } from '../../helpers/http';

const { baseUrl } = wireConfig();
const documentUrl = serverPath(baseUrl, '/.well-known/oauth-authorization-server');

describe('RFC 8414 §3 — authorization server metadata, over HTTP', () => {
  it('answers a GET at the well-known URL with 200 and an application/json object (§3.1, §3.2)', async () => {
    const { body } = await getJsonObject(documentUrl);

    expect(Object.keys(body).length).toBeGreaterThan(0);
  });

  it('reports an issuer identical to the issuer identifier the well-known URL was built from (§3.3)', async () => {
    const { body } = await getJsonObject(documentUrl);

    expect(body['issuer']).toBe(baseUrl);
  });
});
