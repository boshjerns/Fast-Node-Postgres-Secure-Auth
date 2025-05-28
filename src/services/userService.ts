import pool from '../config/database';
import { User, CreateUserData, LoginData, UserResponse, RefreshToken } from '../models/User';
import { hashPassword, comparePassword, sanitizeUser, generateTokenHash } from '../utils/auth';

export class UserService {
  /**
   * Create a new user
   */
  static async createUser(userData: CreateUserData): Promise<UserResponse> {
    const client = await pool.connect();
    
    try {
      // Check if username or email already exists
      const existingUser = await client.query(
        'SELECT id FROM users WHERE username = $1 OR email = $2',
        [userData.username, userData.email]
      );

      if (existingUser.rows.length > 0) {
        throw new Error('Username or email already exists');
      }

      // Hash the password
      const passwordHash = await hashPassword(userData.password);

      // Insert new user
      const result = await client.query(
        `INSERT INTO users (username, email, password_hash) 
         VALUES ($1, $2, $3) 
         RETURNING id, username, email, created_at, is_active`,
        [userData.username, userData.email, passwordHash]
      );

      return result.rows[0];
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Authenticate user login
   */
  static async authenticateUser(loginData: LoginData): Promise<UserResponse | null> {
    const client = await pool.connect();
    
    try {
      // Get user by username
      const result = await client.query(
        'SELECT * FROM users WHERE username = $1 AND is_active = true',
        [loginData.username]
      );

      if (result.rows.length === 0) {
        return null;
      }

      const user: User = result.rows[0];

      // Check if account is locked
      if (user.locked_until && new Date() < user.locked_until) {
        throw new Error('Account is temporarily locked due to too many failed login attempts');
      }

      // Verify password
      const isValidPassword = await comparePassword(loginData.password, user.password_hash);

      if (!isValidPassword) {
        // Increment failed login attempts
        await this.incrementFailedLoginAttempts(user.id);
        return null;
      }

      // Reset failed login attempts and update last login
      await client.query(
        'UPDATE users SET failed_login_attempts = 0, last_login = CURRENT_TIMESTAMP, locked_until = NULL WHERE id = $1',
        [user.id]
      );

      return sanitizeUser(user);
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Get user by ID
   */
  static async getUserById(userId: number): Promise<UserResponse | null> {
    const client = await pool.connect();
    
    try {
      const result = await client.query(
        'SELECT * FROM users WHERE id = $1 AND is_active = true',
        [userId]
      );

      if (result.rows.length === 0) {
        return null;
      }

      return sanitizeUser(result.rows[0]);
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Get user by username
   */
  static async getUserByUsername(username: string): Promise<UserResponse | null> {
    const client = await pool.connect();
    
    try {
      const result = await client.query(
        'SELECT * FROM users WHERE username = $1 AND is_active = true',
        [username]
      );

      if (result.rows.length === 0) {
        return null;
      }

      return sanitizeUser(result.rows[0]);
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Store refresh token
   */
  static async storeRefreshToken(userId: number, refreshToken: string, expiresAt: Date): Promise<void> {
    const client = await pool.connect();
    
    try {
      const tokenHash = generateTokenHash(refreshToken);
      
      await client.query(
        'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
        [userId, tokenHash, expiresAt]
      );
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Verify refresh token
   */
  static async verifyRefreshToken(refreshToken: string): Promise<RefreshToken | null> {
    const client = await pool.connect();
    
    try {
      const tokenHash = generateTokenHash(refreshToken);
      
      const result = await client.query(
        'SELECT * FROM refresh_tokens WHERE token_hash = $1 AND expires_at > CURRENT_TIMESTAMP AND is_revoked = false',
        [tokenHash]
      );

      if (result.rows.length === 0) {
        return null;
      }

      return result.rows[0];
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Revoke refresh token
   */
  static async revokeRefreshToken(refreshToken: string): Promise<void> {
    const client = await pool.connect();
    
    try {
      const tokenHash = generateTokenHash(refreshToken);
      
      await client.query(
        'UPDATE refresh_tokens SET is_revoked = true WHERE token_hash = $1',
        [tokenHash]
      );
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Revoke all refresh tokens for a user
   */
  static async revokeAllRefreshTokens(userId: number): Promise<void> {
    const client = await pool.connect();
    
    try {
      await client.query(
        'UPDATE refresh_tokens SET is_revoked = true WHERE user_id = $1',
        [userId]
      );
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Increment failed login attempts
   */
  private static async incrementFailedLoginAttempts(userId: number): Promise<void> {
    const client = await pool.connect();
    
    try {
      // Increment failed attempts
      await client.query(
        'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1',
        [userId]
      );

      // Check if we need to lock the account (after 5 failed attempts)
      const result = await client.query(
        'SELECT failed_login_attempts FROM users WHERE id = $1',
        [userId]
      );

      const failedAttempts = result.rows[0]?.failed_login_attempts || 0;

      if (failedAttempts >= 5) {
        // Lock account for 30 minutes
        await client.query(
          'UPDATE users SET locked_until = CURRENT_TIMESTAMP + INTERVAL \'30 minutes\' WHERE id = $1',
          [userId]
        );
      }
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Clean up expired refresh tokens
   */
  static async cleanupExpiredTokens(): Promise<void> {
    const client = await pool.connect();
    
    try {
      await client.query(
        'DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP OR is_revoked = true'
      );
    } catch (error) {
      throw error;
    } finally {
      client.release();
    }
  }
} 