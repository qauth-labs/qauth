import { createPublicKey, type KeyObject } from 'node:crypto';

import type { JWK } from 'jose';

import { createInProcessSigner } from '../lib/in-process-signer';
import { createKeyFactory } from '../lib/key-factory';
import { createPublishedKeyReader, type PublishedKeyReader } from '../lib/published-keys';
import type { Signer } from '../lib/signer';
import { KEK_A, localProvider } from './keks';
import { createMemoryKeyStore } from './memory-key-store';
import { createMemorySignerStore, type MemorySignerStore } from './memory-signer-store';
import { testCertificateFor } from './test-certificate';

/**
 * TEST SUPPORT — a realm's in-process signer for the signer service's and
 * the remote signer's unit tests (#497). Never exported from the package
 * entry point.
 *
 * One realm, every standard key provisioned, a webhook secret for
 * {@link SERVICE_SUBSCRIPTION}, a client-assertion key and configuration for
 * {@link SERVICE_PROVIDER}, and an OID4VP request key with a certificate
 * that names it.
 */

export const SERVICE_REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e11';
export const SERVICE_ISSUER = 'https://service.example.test';
export const SERVICE_SUBSCRIPTION = 'subscription-1';
export const SERVICE_PROVIDER = 'provider-1';
export const SERVICE_NOW = 1_800_000_000_000;

/** What {@link createServiceSigner} made. */
export interface ServiceSigner {
  readonly signer: Signer;
  readonly store: MemorySignerStore;
  /** The realm's published keys, as a process without the signer reads them. */
  readonly publishedKeys: PublishedKeyReader;
  /** The webhook secret `createKey` showed, `whsec_…`. */
  readonly webhookSecret: string;
  /** The verifier's certificate chain, naming the OID4VP request key. */
  readonly verifierChain: readonly string[];
}

function publicKeyOf(jwk: JWK | undefined): KeyObject {
  if (jwk === undefined) throw new Error('no public JWK');
  return createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' });
}

/** Make the realm's keys and its in-process signer. */
export async function createServiceSigner(
  options: { readonly hybrid?: boolean } = {}
): Promise<ServiceSigner> {
  const hybrid = options.hybrid === true;
  const enabled = hybrid ? (['EdDSA', 'ML-DSA-65'] as const) : (['EdDSA'] as const);
  const keys = createMemoryKeyStore();
  const kekProvider = localProvider({ KEK: KEK_A });
  const factory = createKeyFactory({
    store: keys,
    kekProvider,
    enabledSignatureAlgorithms: enabled,
    hybridSigning: hybrid,
    now: () => SERVICE_NOW,
  });
  await factory.provisionRealmKeys(SERVICE_REALM);
  const [webhook] = await factory.createKey({
    realmId: SERVICE_REALM,
    purpose: 'webhook_signing',
    scopeId: SERVICE_SUBSCRIPTION,
  });
  await factory.createKey({
    realmId: SERVICE_REALM,
    purpose: 'upstream_client_assertion',
    scopeId: SERVICE_PROVIDER,
  });
  const [verifier] = await factory.createKey({
    realmId: SERVICE_REALM,
    purpose: 'oid4vp_request_signing',
  });
  const store = createMemorySignerStore(keys, { [SERVICE_REALM]: SERVICE_ISSUER });
  store.upstreamClients.set(`${SERVICE_REALM}/${SERVICE_PROVIDER}`, { clientId: 'qauth-rp' });
  const signer = createInProcessSigner({
    store,
    kekProvider,
    enabledSignatureAlgorithms: enabled,
    hybridSigning: hybrid,
    now: () => SERVICE_NOW,
  });
  return {
    signer,
    store,
    publishedKeys: createPublishedKeyReader(store, { now: () => SERVICE_NOW }),
    webhookSecret: webhook.secret as string,
    verifierChain: [testCertificateFor(publicKeyOf(verifier.publicJwk))],
  };
}
