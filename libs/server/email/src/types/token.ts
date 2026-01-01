/**
 * Token pair containing the plain token and its hash
 * The token is sent to the user, the hash is stored in the database
 */
export interface TokenPair {
  /** Plain token (64-character hex string) - send to user */
  token: string;
  /** SHA-256 hash of the token (64-character hex string) - store in database */
  tokenHash: string;
}
