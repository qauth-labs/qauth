/**
 * Error thrown when a client registration carries a metadata value the server
 * refuses (RFC 7591 §3.2.2 `invalid_client_metadata`): a field the schema
 * rejects, or a value the realm's registration policy does not allow.
 *
 * Wire format mirrors RFC 7591 §3.2.2: `error` carries the bare
 * `invalid_client_metadata` token, with optional `error_description` for
 * human-readable detail.
 */
export class InvalidClientMetadataError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_CLIENT_METADATA';
  readonly errorDescription?: string;

  constructor(errorDescription?: string) {
    super('invalid_client_metadata');
    this.name = 'InvalidClientMetadataError';
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, InvalidClientMetadataError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidClientMetadataError);
    }
  }
}
