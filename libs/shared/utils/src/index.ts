// Utility functions for QAuth OAuth 2.1/OIDC server

import {
  ACCESS_TOKEN_LENGTH,
  AUTHORIZATION_CODE_LENGTH,
  OAUTH_CODE_ALPHABET,
  REFRESH_TOKEN_LENGTH,
  SESSION_ID_LENGTH,
  TOKEN_ALPHABET,
} from '@qauth/constants';
import { customAlphabet } from 'nanoid';

// =============================================================================
// ID Generation Utilities
// =============================================================================

/**
 * Generate cryptographically secure authorization code
 * Uses custom alphabet for OAuth codes (alphanumeric only)
 */
export const generateAuthorizationCode = customAlphabet(
  OAUTH_CODE_ALPHABET,
  AUTHORIZATION_CODE_LENGTH
);

/**
 * Generate cryptographically secure access token
 * URL-safe alphabet for JWT compatibility
 */
export const generateAccessToken = customAlphabet(TOKEN_ALPHABET, ACCESS_TOKEN_LENGTH);

/**
 * Generate cryptographically secure refresh token
 * URL-safe alphabet for storage compatibility
 */
export const generateRefreshToken = customAlphabet(TOKEN_ALPHABET, REFRESH_TOKEN_LENGTH);

/**
 * Generate cryptographically secure session ID
 * Shorter length for session management efficiency
 */
export const generateSessionId = customAlphabet(TOKEN_ALPHABET, SESSION_ID_LENGTH);

// =============================================================================
// Time Utilities
// =============================================================================

/**
 * Get current timestamp as Date object
 */
export const now = (): Date => new Date();

/**
 * Add seconds to a date and return new Date
 */
export const addSeconds = (date: Date, seconds: number): Date => {
  return new Date(date.getTime() + seconds * 1000);
};

/**
 * Check if a date has expired (is in the past)
 */
export const isExpired = (date: Date): boolean => {
  return date.getTime() <= now().getTime();
};

/**
 * Get seconds until expiration from now
 */
export const secondsUntilExpiration = (expiresAt: Date): number => {
  const now = Date.now();
  const expires = expiresAt.getTime();
  return Math.max(0, Math.floor((expires - now) / 1000));
};

// =============================================================================
// Validation Utilities
// =============================================================================

/**
 * Validate email format using regex
 */
export const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate URL format
 */
export const isValidUrl = (url: string): boolean => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

/**
 * Validate redirect URI for OAuth
 * Must be absolute URL (http/https) or custom scheme
 */
export const isValidRedirectUri = (uri: string): boolean => {
  try {
    const url = new URL(uri);
    // Allow http/https or custom schemes
    return (
      url.protocol === 'http:' ||
      url.protocol === 'https:' ||
      /^[a-zA-Z][a-zA-Z0-9+.-]*:$/.test(url.protocol)
    );
  } catch {
    return false;
  }
};

/**
 * Validate scope format
 * Scopes should be space-separated strings
 */
export const isValidScope = (scope: string): boolean => {
  const scopeRegex = /^[a-zA-Z0-9._-]+(\s+[a-zA-Z0-9._-]+)*$/;
  return scopeRegex.test(scope);
};

/**
 * Parse scopes string into array
 */
export const parseScopes = (scopeString: string): string[] => {
  return scopeString.trim().split(/\s+/).filter(Boolean);
};

/**
 * Join scopes array into string
 */
export const joinScopes = (scopes: string[]): string => {
  return scopes.join(' ');
};

// =============================================================================
// String Utilities
// =============================================================================

/**
 * Generate random string of specified length
 */
export const generateRandomString = (length: number): string => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

/**
 * Truncate string to specified length with ellipsis
 */
export const truncate = (str: string, length: number): string => {
  if (str.length <= length) return str;
  return str.substring(0, length - 3) + '...';
};

/**
 * Convert string to slug (URL-safe)
 */
export const slugify = (str: string): string => {
  return str
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
};

// =============================================================================
// Array Utilities
// =============================================================================

/**
 * Remove duplicates from array
 */
export const unique = <T>(array: T[]): T[] => {
  return [...new Set(array)];
};

/**
 * Check if two arrays have the same elements (order independent)
 */
export const arraysEqual = <T>(a: T[], b: T[]): boolean => {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((val, index) => val === sortedB[index]);
};

/**
 * Check if array contains all elements from another array
 */
export const containsAll = <T>(array: T[], elements: T[]): boolean => {
  return elements.every((element) => array.includes(element));
};

// =============================================================================
// Object Utilities
// =============================================================================

/**
 * Deep clone an object
 */
export const deepClone = <T>(obj: T): T => {
  return JSON.parse(JSON.stringify(obj));
};

/**
 * Pick specific properties from object
 */
export const pick = <T extends Record<string, any>, K extends keyof T>(
  obj: T,
  keys: K[]
): Pick<T, K> => {
  const result = {} as Pick<T, K>;
  keys.forEach((key) => {
    if (key in obj) {
      result[key] = obj[key];
    }
  });
  return result;
};

/**
 * Omit specific properties from object
 */
export const omit = <T extends Record<string, any>, K extends keyof T>(
  obj: T,
  keys: K[]
): Omit<T, K> => {
  const result = { ...obj };
  keys.forEach((key) => {
    delete result[key];
  });
  return result;
};

// =============================================================================
// Error Utilities
// =============================================================================

/**
 * Create standardized error object
 */
export const createError = (code: string, message: string, statusCode = 500, details?: any) => {
  const error = new Error(message) as any;
  error.code = code;
  error.statusCode = statusCode;
  error.details = details;
  return error;
};

/**
 * Check if error is a known error type
 */
export const isKnownError = (error: any): error is { code: string; statusCode: number } => {
  return error && typeof error.code === 'string' && typeof error.statusCode === 'number';
};

// =============================================================================
// Crypto Utilities
// =============================================================================

/**
 * Generate secure random bytes (for nonces, etc.)
 */
export const generateRandomBytes = (length: number): Uint8Array => {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    // Browser or Node.js with crypto
    return crypto.getRandomValues(new Uint8Array(length));
  }

  // Fallback for older environments
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
};

/**
 * Convert bytes to hex string
 */
export const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

/**
 * Convert hex string to bytes
 */
export const hexToBytes = (hex: string): Uint8Array => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
};

// =============================================================================
// Environment Utilities
// =============================================================================

/**
 * Get environment variable with fallback
 */
export const getEnv = (key: string, fallback?: string): string | undefined => {
  return process.env[key] || fallback;
};

/**
 * Get required environment variable
 */
export const getRequiredEnv = (key: string): string => {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Required environment variable ${key} is not set`);
  }
  return value;
};

/**
 * Get environment variable as number
 */
export const getEnvAsNumber = (key: string, fallback?: number): number | undefined => {
  const value = process.env[key];
  if (!value) return fallback;

  const parsed = parseInt(value, 10);
  if (isNaN(parsed)) {
    throw new Error(`Environment variable ${key} must be a valid number, got: ${value}`);
  }
  return parsed;
};

/**
 * Get environment variable as boolean
 */
export const getEnvAsBoolean = (key: string, fallback?: boolean): boolean | undefined => {
  const value = process.env[key];
  if (!value) return fallback;

  const lowerValue = value.toLowerCase();
  if (lowerValue === 'true' || lowerValue === '1') return true;
  if (lowerValue === 'false' || lowerValue === '0') return false;

  throw new Error(
    `Environment variable ${key} must be a valid boolean (true/false, 1/0), got: ${value}`
  );
};
