import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { getJsonObject } from '../../helpers/http';

const { baseUrl } = wireConfig();
const documentUrl = serverPath(baseUrl, '/.well-known/openid-configuration');

describe('OIDC Discovery 1.0 §4 — the provider configuration document, over HTTP', () => {
  it('answers a GET at the issuer plus the well-known path with 200 and an application/json object (§4.1, §4.2)', async () => {
    const { body } = await getJsonObject(documentUrl);

    expect(Object.keys(body).length).toBeGreaterThan(0);
  });

  it('reports an issuer identical to the base URL the document was fetched from (§4.3)', async () => {
    const { body } = await getJsonObject(documentUrl);

    expect(body['issuer']).toBe(baseUrl);
  });
});
