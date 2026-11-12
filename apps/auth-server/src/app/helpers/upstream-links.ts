import {
  isUpstreamCredentialData,
  PASSWORD_PROVIDER_TYPE,
  UPSTREAM_CREDENTIAL_KIND,
} from '@qauth-labs/fastify-plugin-federation';
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { readPage } from '../api-conventions/cursor';
import type { Page } from '../api-conventions/paging';
import type { EngineMailer, MailRealm } from './engine-mail';
import type { UpstreamLink } from './interaction-record';
import { buildRealmUrl } from './realm-url';
import type { RealmRow } from './request-realm';
import { upstreamProviderCatalog } from './upstream-providers';
import { emitUserEvent } from './user-events';

/**
 * THE UPSTREAM ACCOUNT LINKS (#670; ADR-020 §3, ADR-019 Decision 7, NIST SP
 * 800-63C-4 §5.4 "an authenticated session for all linking functions").
 *
 * An upstream identity joins an existing account only once the person signed
 * in to that account, with its own factors or through another upstream
 * provider it already holds (#1080), under its MFA policy, in the browser
 * and the interaction in which the provider proved the identity:
 * {@link finishHeldUpstreamLink} calls {@link linkUpstreamIdentity} once such
 * a sign-in finished (`routes/interaction-api.ts`, or the provider's callback
 * when the provider's proof finished it). The account API removes one with
 * {@link unlinkUpstreamIdentity}, behind its fresh-authentication guard. An
 * admin never links one (ADR-019 Decision 7).
 *
 * The account is never found by an attribute: the caller names it by the
 * sign-in that just completed, and the identity by the provider's
 * `(type, sub, iss)`. No email address is read here.
 *
 * - **One account per identity.** The realm's unique index on
 *   `(realm, provider type, external sub)` makes an identity another account
 *   holds `already_linked`, also when two links race.
 * - **One identity per provider and account.** An account that already holds
 *   an identity of the provider is refused with `provider_linked`.
 * - **The last way in.** An unlink that would leave the account with no
 *   credential to sign in with (a password, a passkey, an upstream identity,
 *   a wallet) is refused with `last_credential`. An authenticator app is a
 *   second factor, never a way in on its own; a marked credential, or the
 *   identity of a provider switched off, signs in with none (#844).
 *
 * Each change locks the user's row, so a link, an unlink and its
 * last-credential check of one account never interleave, and its event
 * (`user.upstream_linked`, `user.upstream_unlinked`) commits with it; a
 * refused link is recorded as `user.upstream_link_failed`. The owner is
 * told by email, at the address of the account's password, after the
 * commit; an account with no password has the security log alone.
 *
 * A link stores the credential alone, `verified: true`: the account was
 * proved by its own sign-in, so the identity neither adds nor removes its
 * verification, and none of the provider's claims becomes an attribute, so
 * no claim of the provider changes what the account's tokens say. An unlink
 * leaves the attributes the provider gave when it created the account.
 */

/** An upstream identity a provider proved: its provider's type, subject and issuer. */
export interface UpstreamIdentity {
  /** The provider's AuthMethod type (`oidc_corp`), the credential's `provider_type`. */
  readonly provider: string;
  /** The provider's subject, the credential's `external_sub`. */
  readonly externalSub: string;
  /** The issuer that named the subject. */
  readonly iss: string;
}

/** Why a link was refused, as `user.upstream_link_failed` records it. */
export type UpstreamLinkRefusal = 'already_linked' | 'provider_linked' | 'account_unavailable';

/** What {@link linkUpstreamIdentity} did. */
export type LinkUpstreamResult =
  /**
   * The identity belongs to the account now: `created` when this call linked
   * it, `false` when the account already held it (a finish that ran twice).
   */
  | { readonly kind: 'linked'; readonly credentialId: string; readonly created: boolean }
  | { readonly kind: 'refused'; readonly reason: UpstreamLinkRefusal };

/** What {@link linkUpstreamIdentity} and {@link unlinkUpstreamIdentity} need of the server. */
export type UpstreamLinkServer = Pick<FastifyInstance, 'db' | 'repositories' | 'log'> &
  Parameters<typeof upstreamProviderCatalog>[0];

/** The input of {@link linkUpstreamIdentity}. */
export interface LinkUpstreamInput {
  readonly realm: MailRealm & Pick<RealmRow, 'id'>;
  /** The account the person just signed in to, in the interaction the provider proved the identity in. */
  readonly userId: string;
  readonly identity: UpstreamIdentity;
  /** The provider's name as the operator set it, for the notice. */
  readonly providerName: string;
  /** The `client_id` the interaction is for, for the events; `null` when it cannot be carried. */
  readonly clientId: string | null;
  readonly mailer: EngineMailer;
}

/**
 * Link `identity` to the account `userId` (#670). The caller has checked that
 * the person signed in to that account with its own factors, in the
 * interaction and the browser the provider proved the identity in; this
 * checks the account is still there and enabled, the identity free, and the
 * account without another identity of the provider, then writes the
 * credential and its event in one transaction and tells the owner.
 */
export async function linkUpstreamIdentity(
  fastify: UpstreamLinkServer,
  request: FastifyRequest,
  input: LinkUpstreamInput
): Promise<LinkUpstreamResult> {
  const { repositories } = fastify;
  const { realm, userId, identity } = input;
  const refused = (reason: UpstreamLinkRefusal) => ({ kind: 'refused', reason }) as const;
  let result: LinkUpstreamResult;
  try {
    result = await fastify.db.transaction(async (tx): Promise<LinkUpstreamResult> => {
      if (!(await repositories.userCredentials.lockUser(realm.id, userId, tx))) {
        return refused('account_unavailable');
      }
      const user = await repositories.users.findById(realm.id, userId, tx);
      // The sign-in that just finished proved the account after any earlier
      // disablement: only one disabled since refuses the link.
      if (user === undefined || !user.enabled) {
        return refused('account_unavailable');
      }
      const held = await repositories.userCredentials.findByRealmProviderSub(
        realm.id,
        identity.provider,
        identity.externalSub,
        tx
      );
      if (held !== undefined) {
        return held.userId === userId
          ? { kind: 'linked', credentialId: held.id, created: false }
          : refused('already_linked');
      }
      const sameProvider = await repositories.userCredentials.findAllByUserIdAndType(
        userId,
        identity.provider,
        tx
      );
      if (sameProvider.length > 0) return refused('provider_linked');
      const credential = await repositories.userCredentials.create(
        {
          userId,
          realmId: realm.id,
          providerType: identity.provider,
          externalSub: identity.externalSub,
          credentialData: { kind: UPSTREAM_CREDENTIAL_KIND, iss: identity.iss, verified: true },
        },
        tx
      );
      await emitUserEvent(
        request,
        'urn:qauth:event:user.upstream_linked:v1-rc.0',
        { provider: identity.provider, credentialId: credential.id },
        { tx, realmId: realm.id, userId, clientId: input.clientId, actor: 'user' }
      );
      return { kind: 'linked', credentialId: credential.id, created: true };
    });
  } catch (error) {
    // Another account took the identity between the read and the insert.
    if (!(error instanceof UniqueConstraintError)) throw error;
    result = refused('already_linked');
  }
  if (result.kind === 'refused') {
    await emitUserEvent(
      request,
      'urn:qauth:event:user.upstream_link_failed:v1-rc.0',
      { provider: identity.provider, reason: result.reason },
      { realmId: realm.id, userId, clientId: input.clientId, actor: 'user' }
    );
    return result;
  }
  if (result.created) {
    await notifyOwner(fastify, input.mailer, realm, userId, {
      template: 'upstream_linked',
      providerName: input.providerName,
    });
  }
  return result;
}

/** What {@link finishHeldUpstreamLink} did. */
export type HeldUpstreamLinkOutcome =
  /** The interaction held no identity to attach: no link, or one whose provider proved nobody yet. */
  | { readonly kind: 'none' }
  /** The identity belongs to the account the sign-in proved. */
  | { readonly kind: 'linked' }
  /** The link was refused and recorded: the browser goes to its page, `location`. */
  | { readonly kind: 'refused'; readonly location: string };

/** The input of {@link finishHeldUpstreamLink}. */
export interface HeldUpstreamLinkInput {
  readonly realm: RealmRow;
  /** The upstream link the finished interaction holds, if any. */
  readonly link: UpstreamLink | undefined;
  /** Who the interaction's sign-in proved, and whether it was a registration. */
  readonly transaction: { readonly userId?: string; readonly registered?: boolean };
  /** The `client_id` the interaction is for, for the events; `null` when it cannot be carried. */
  readonly clientId: string | null;
  readonly mailer: EngineMailer;
}

/**
 * Attach the upstream identity a finished interaction holds (#670) to the
 * account its sign-in proved, in that interaction and its browser: by the
 * account's own factors, or through another upstream provider the account
 * already holds (#1080). The Interaction API and the providers' callback
 * both finish such a sign-in, the latter when the provider's proof completes
 * it. A link whose provider proved nobody yet (`requested`) holds no
 * identity, and nothing is attached. A held identity after anything but a
 * sign-in is a record no server writes: thrown, before anything is linked.
 */
export async function finishHeldUpstreamLink(
  fastify: UpstreamLinkServer,
  request: FastifyRequest,
  input: HeldUpstreamLinkInput
): Promise<HeldUpstreamLinkOutcome> {
  const { link, transaction, realm } = input;
  if (link === undefined || link.state === 'requested') return { kind: 'none' };
  if (
    link.state !== 'signing_in' ||
    transaction.userId === undefined ||
    transaction.registered === true
  ) {
    throw new Error('an interaction finished with a link it never signed in for');
  }
  const linked = await linkUpstreamIdentity(fastify, request, {
    realm,
    userId: transaction.userId,
    identity: { provider: link.provider, externalSub: link.externalSub, iss: link.iss },
    providerName: link.name,
    clientId: input.clientId,
    mailer: input.mailer,
  });
  if (linked.kind === 'linked') return { kind: 'linked' };
  const search = new URLSearchParams({ provider: link.provider, reason: linked.reason });
  return {
    kind: 'refused',
    location: buildRealmUrl(realm, `/ui/upstream-link-refused?${search.toString()}`),
  };
}

/** What {@link unlinkUpstreamIdentity} did. */
export type UnlinkUpstreamResult =
  | { readonly kind: 'unlinked' }
  /** No upstream identity of the account has that id: another account's reads the same. */
  | { readonly kind: 'not_found' }
  /** The identity is the account's last way to sign in. */
  | { readonly kind: 'last_credential' };

/** The input of {@link unlinkUpstreamIdentity}. */
export interface UnlinkUpstreamInput {
  readonly realm: MailRealm & Pick<RealmRow, 'id'>;
  /** The token's user, whose fresh sign-in the account API's guard checked. */
  readonly userId: string;
  /** The linked account's id: the credential's. */
  readonly credentialId: string;
  readonly mailer: EngineMailer;
}

/**
 * Whether a credential lets the account sign in on its own: anything but an
 * authenticator app, which is a second factor (ADR-017 Decision 8).
 */
function signsIn(credential: { readonly providerType: string }): boolean {
  return credential.providerType !== 'totp';
}

/** A credential, as far as {@link signsInNow} reads it. */
export interface WayInCandidate {
  readonly providerType: string;
  readonly credentialData?: unknown;
  /** The failure ladder's mark, or a rebind's (#655). */
  readonly disabledAt?: number | null;
}

/**
 * Whether one of `credentials` still signs the account in on its own: an
 * unmarked credential that is no authenticator app and, for an upstream
 * identity, one whose provider the realm has on. A credential the failure
 * ladder or a rebind marked signs in with nothing until a reset or a new
 * set-up, nor does the identity of a provider switched off (#844), so
 * neither is a way in a removal may leave the account with. A provider is
 * read only when nothing else signs in.
 */
export async function signsInNow(
  fastify: UpstreamLinkServer,
  realmId: string,
  credentials: readonly WayInCandidate[]
): Promise<boolean> {
  const live = credentials.filter(
    (credential) =>
      signsIn(credential) && (credential.disabledAt === null || credential.disabledAt === undefined)
  );
  if (live.some((credential) => !isUpstreamCredentialData(credential.credentialData))) return true;
  const catalog = upstreamProviderCatalog(fastify);
  for (const credential of live) {
    if ((await catalog.find(realmId, credential.providerType)) !== undefined) return true;
  }
  return false;
}

/**
 * Remove the upstream identity `credentialId` from the account `userId`
 * (#670). Its caller, the account API, has checked a fresh sign-in and
 * refused an act-chain token. Under the user's row lock: an identity of
 * another account, or a credential that is no upstream identity, is
 * `not_found`; one that is the account's last way to sign in is
 * `last_credential`. The delete and its event commit together, then the
 * owner is told.
 */
export async function unlinkUpstreamIdentity(
  fastify: UpstreamLinkServer,
  request: FastifyRequest,
  input: UnlinkUpstreamInput
): Promise<UnlinkUpstreamResult> {
  const { repositories } = fastify;
  const { realm, userId, credentialId } = input;
  const outcome = await fastify.db.transaction(
    async (tx): Promise<UnlinkUpstreamResult | { kind: 'deleted'; provider: string }> => {
      if (!(await repositories.userCredentials.lockUser(realm.id, userId, tx))) {
        return { kind: 'not_found' };
      }
      const credentials = await repositories.userCredentials.findAllByUserId(userId, tx);
      const target = credentials.find(
        (credential) =>
          credential.id === credentialId &&
          credential.realmId === realm.id &&
          isUpstreamCredentialData(credential.credentialData)
      );
      if (target === undefined) return { kind: 'not_found' };
      const others = credentials.filter(
        (credential) => credential.id !== target.id && credential.realmId === realm.id
      );
      if (!(await signsInNow(fastify, realm.id, others))) return { kind: 'last_credential' };
      const deleted = await repositories.userCredentials.deleteById(realm.id, target.id, tx);
      if (deleted === undefined || deleted.userId !== userId) {
        throw new Error('a locked credential could not be deleted');
      }
      await emitUserEvent(
        request,
        'urn:qauth:event:user.upstream_unlinked:v1-rc.0',
        { provider: target.providerType, credentialId: target.id },
        { tx, realmId: realm.id, userId, actor: 'user' }
      );
      return { kind: 'deleted', provider: target.providerType };
    }
  );
  if (outcome.kind !== 'deleted') return outcome;
  const provider = await upstreamProviderCatalog(fastify).find(realm.id, outcome.provider);
  await notifyOwner(fastify, input.mailer, realm, userId, {
    template: 'upstream_unlinked',
    // A provider switched off since keeps its type as its name.
    providerName: provider?.entry.name ?? outcome.provider,
  });
  return { kind: 'unlinked' };
}

/** One linked upstream account, as the account API lists it. */
export interface LinkedAccount {
  readonly id: string;
  readonly provider: string;
  /** The provider's name, while the realm has it on. */
  readonly providerName?: string;
  readonly createdAt: number;
}

/**
 * One page of the upstream identities of `userId` (#670), newest first, by
 * when each was linked and then by id. An account holds one per provider,
 * so the list is read whole and paged here.
 */
export async function pageLinkedAccounts(
  fastify: UpstreamLinkServer,
  realmId: string,
  userId: string,
  page: { readonly list: string; readonly limit: number; readonly cursor: string | undefined }
): Promise<Page<LinkedAccount>> {
  const catalog = upstreamProviderCatalog(fastify);
  const rows = (await fastify.repositories.userCredentials.findAllByUserId(userId))
    .filter(
      (credential) =>
        credential.realmId === realmId && isUpstreamCredentialData(credential.credentialData)
    )
    .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
  return readPage<(typeof rows)[number], LinkedAccount>(
    {
      list: page.list,
      limit: page.limit,
      cursor: page.cursor,
      position: (row) => ({ at: row.createdAt, id: row.id }),
      item: async (row): Promise<LinkedAccount> => {
        const provider = await catalog.find(realmId, row.providerType);
        return {
          id: row.id,
          provider: row.providerType,
          ...(provider === undefined ? {} : { providerName: provider.entry.name }),
          createdAt: row.createdAt,
        };
      },
    },
    async ({ limit, after }) =>
      rows
        .filter(
          (row) =>
            after === undefined ||
            row.createdAt < after.at ||
            (row.createdAt === after.at && row.id < after.id)
        )
        .slice(0, limit)
  );
}

/**
 * Tell the owner of `userId` by email, at the address of its password, after
 * the change committed. A notice that cannot go out is logged: the change
 * stands, and the security log has it.
 */
async function notifyOwner(
  fastify: UpstreamLinkServer,
  mailer: EngineMailer,
  realm: MailRealm,
  userId: string,
  mail: {
    readonly template: 'upstream_linked' | 'upstream_unlinked';
    readonly providerName: string;
  }
): Promise<void> {
  try {
    const password = await fastify.repositories.userCredentials.findByUserIdAndType(
      userId,
      PASSWORD_PROVIDER_TYPE
    );
    if (password === undefined || password.realmId !== realm.id) return;
    mailer.sendUncounted(
      realm,
      password.externalSub,
      mail.template === 'upstream_linked'
        ? { template: 'upstream_linked', providerName: mail.providerName }
        : { template: 'upstream_unlinked', providerName: mail.providerName }
    );
  } catch (error) {
    fastify.log.error(
      { err: error, realmId: realm.id },
      'an upstream account changed, but its notice failed'
    );
  }
}
