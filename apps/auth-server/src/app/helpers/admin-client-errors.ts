/**
 * A client the admin API may read but not change (ADR-012 Decision 3, issue
 * #632): a client registered from a Client ID Metadata Document takes its
 * settings from that document, which every resolution rewrites the row
 * from. A change here would look saved and then be undone, so it is refused:
 * `409`, the `conflict` problem document, naming the document to change
 * instead. Its URL is the client's `client_id`, no secret.
 */
/**
 * An admin deletion of a client a service account binds (#522): the service
 * account is its client's, and goes first. 409, as the database's foreign key
 * would refuse the deletion anyway.
 */
export class ClientOfServiceAccountError extends Error {
  readonly statusCode = 409;
  readonly code = 'CONFLICT';

  constructor() {
    super(
      "The client is a service account's: remove or disable the service account first, and the client goes with it"
    );
    this.name = 'ClientOfServiceAccountError';
  }
}

export class ClientManagedByDocumentError extends Error {
  readonly statusCode = 409;
  readonly code = 'CONFLICT';

  constructor(readonly document: string) {
    super(
      `The client's settings come from its Client ID Metadata Document, ${document}: change the document, not the client`
    );
    this.name = 'ClientManagedByDocumentError';
  }
}
