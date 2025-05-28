import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { User, UserResponse } from '../models/User';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12');

export interface JWTPayload {
  userId: number;
  username: string;
  iat?: number;
  exp?: number;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

/**
 * Hash a password using bcrypt
 */
export const hashPassword = async (password: string): Promise<string> => {
  return await bcrypt.hash(password, BCRYPT_ROUNDS);
};

/**
 * Compare a password with its hash
 */
export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
};

/**
 * Generate JWT access token
 */
export const generateAccessToken = (user: User | UserResponse): string => {
  const payload: JWTPayload = {
    userId: user.id,
    username: user.username,
  };
  console.log('[AuthUtil] Generating Access Token with payload:', payload);
  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    issuer: 'secure-auth-app',
    audience: 'secure-auth-app-users',
  } as jwt.SignOptions);
  console.log('[AuthUtil] Access Token generated (first 10 chars):', token.substring(0, 10) + '...');
  return token;
};

/**
 * Generate JWT refresh token
 */
export const generateRefreshToken = (user: User | UserResponse): string => {
  const payload: JWTPayload = {
    userId: user.id,
    username: user.username,
  };
  console.log('[AuthUtil] Generating Refresh Token with payload:', payload);
  const token = jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: '7d', // Typically longer expiry for refresh tokens
    issuer: 'secure-auth-app',
    audience: 'secure-auth-app-users',
  } as jwt.SignOptions);
  console.log('[AuthUtil] Refresh Token generated (first 10 chars):', token.substring(0, 10) + '...');
  return token;
};

/**
 * Generate both access and refresh tokens
 */
export const generateTokenPair = (user: User | UserResponse): TokenPair => {
  console.log('[AuthUtil] Generating Token Pair for user ID:', user.id);
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  return {
    accessToken,
    refreshToken,
  };
};

/**
 * Verify JWT access token
 */
export const verifyAccessToken = (token: string): JWTPayload => {
  console.log('[AuthUtil] Verifying Access Token (first 10 chars):', token.substring(0, 10) + '...');
  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: 'secure-auth-app',
      audience: 'secure-auth-app-users',
    }) as JWTPayload;
    console.log('[AuthUtil] Access Token VERIFIED. Payload:', payload);
    return payload;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('[AuthUtil] Access Token VERIFICATION FAILED:', message);
    throw new Error('Invalid or expired access token');
  }
};

/**
 * Verify JWT refresh token
 */
export const verifyRefreshToken = (token: string): JWTPayload => {
  console.log('[AuthUtil] Verifying Refresh Token (first 10 chars):', token.substring(0, 10) + '...');
  try {
    const payload = jwt.verify(token, JWT_REFRESH_SECRET, {
      issuer: 'secure-auth-app',
      audience: 'secure-auth-app-users',
    }) as JWTPayload;
    console.log('[AuthUtil] Refresh Token VERIFIED. Payload:', payload);
    return payload;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('[AuthUtil] Refresh Token VERIFICATION FAILED:', message);
    throw new Error('Invalid or expired refresh token');
  }
};

/**
 * Generate a secure random token hash for refresh token storage
 */
export const generateTokenHash = (token: string): string => {
  console.log('[AuthUtil] Generating hash for token (first 10 chars of token):', token.substring(0, 10) + '...');
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  console.log('[AuthUtil] Token hash generated (first 10 chars of hash):', hash.substring(0, 10) + '...');
  return hash;
};

/**
 * Generate a secure random string
 */
export const generateSecureRandom = (length: number = 32): string => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Sanitize user data for response (remove sensitive fields)
 */
export const sanitizeUser = (user: User): UserResponse => {
  const { password_hash, failed_login_attempts, locked_until, updated_at, ...sanitized } = user;
  return sanitized;
}; 