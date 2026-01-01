/**
 * User data type - can be extended by consumers
 */
export interface UserData {
  [key: string]: unknown;
}

/**
 * User utilities interface
 */
export interface UserUtilsInstance {
  setUserData<T extends UserData>(userId: string, data: T, ttl?: number): Promise<void>;
  getUserData<T extends UserData>(userId: string): Promise<T | null>;
  deleteUserData(userId: string): Promise<void>;
}
