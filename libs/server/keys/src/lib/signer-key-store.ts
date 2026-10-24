import type { KeyIdentity } from './aad';
import type { SealedKeyMaterial } from './envelope';
import type { StoredKeyStatus } from './key-store';

/**
 * What the in-process signer reads (issue #464).
 *
 * This library may not import `@qauth-labs/infra-db`, so it names what it
 * reads, and the signer's wiring adapts the repositories to it:
 * `realms.findById` for the issuer, and `realmKeys.listByRealm`,
 * `realmKeys.getWrappedForSigner` and `realmKeys.listPublicByRealm` for the
 * keys (#461). Nothing here writes: the signer never creates a key.
 */

/** What the signer reads of an upstream provider's configuration (#547). */
export interface UpstreamClientRecord {
  /** The client id QAuth is registered under at the provider: an assertion's `iss` and `sub`. */
  readonly clientId: string;
}

/** A stored key's metadata. No material. */
export interface SignerKeyRecord {
  readonly kid: string;
  readonly algorithm: string;
  readonly status: StoredKeyStatus;
  /** Shared by both keys of a hybrid pair; `null` outside a pair. */
  readonly pairId: string | null;
  /** Epoch ms. When the key stopped signing; `null` while it has not. */
  readonly retireAt: number | null;
  /** Epoch ms. */
  readonly createdAt: number;
}

/** A stored key with its sealed material: the full `realm_keys` row. */
export interface WrappedSignerKey extends KeyIdentity, SealedKeyMaterial {
  readonly status: StoredKeyStatus;
}

/** A `realm_public_keys` row. */
export interface PublicKeyRecord {
  readonly kid: string;
  readonly purpose: string;
  readonly algorithm: string;
  readonly status: StoredKeyStatus;
  readonly publicJwk: Readonly<Record<string, unknown>>;
  /** Epoch ms. The key appears in the JWKS from this moment. */
  readonly publishAt: number;
  /** Epoch ms. The key leaves the JWKS at this moment; `null` while it stays. */
  readonly unpublishAt: number | null;
}

/** The storage the in-process signer reads. */
export interface SignerKeyStore {
  /**
   * The realm's issuer: `undefined` when there is no such realm, `null` when
   * the realm has no issuer yet. An issuer never changes once set (the
   * `realms_issuer_permanent` trigger), so the signer keeps it for good.
   */
  findRealmIssuer(realmId: string): Promise<string | null | undefined>;
  /** Every key of the realm with this purpose and scope, whatever its status. */
  listKeys(
    realmId: string,
    filter: { readonly purpose: string; readonly scopeId: string | null }
  ): Promise<readonly SignerKeyRecord[]>;
  /** One key with its sealed material, or `undefined`. */
  getWrappedKey(realmId: string, kid: string): Promise<WrappedSignerKey | undefined>;
  /** Every published key of the realm, whatever its status or window. */
  listPublicKeys(realmId: string): Promise<readonly PublicKeyRecord[]>;
  /**
   * The realm's configuration of one upstream provider, or `undefined` when
   * the realm has none. Upstream login (ADR-018 §3) owns that configuration;
   * the signer reads only the client id it signs assertions as.
   */
  findUpstreamClient(
    realmId: string,
    providerId: string
  ): Promise<UpstreamClientRecord | undefined>;
}
