import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, JWTPayload } from '../utils/auth';
import { UserService } from '../services/userService';

// Extend Express Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        username: string;
      };
    }
  }
}

/**
 * Middleware to authenticate JWT tokens
 */
export const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  console.log('\n[AuthMiddleware authenticateToken] Checking for token...');
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    console.log('[AuthMiddleware authenticateToken] Auth header:', authHeader ? 'Present' : 'Missing');
    console.log('[AuthMiddleware authenticateToken] Extracted token (first 10 chars):', token ? token.substring(0, 10) + '...' : 'N/A');

    if (!token) {
      console.log('[AuthMiddleware authenticateToken] Access token missing.');
      res.status(401).json({
        success: false,
        message: 'Access token required'
      });
      return;
    }

    // Verify the token
    const payload: JWTPayload = verifyAccessToken(token);
    console.log('[AuthMiddleware authenticateToken] Token verified. Payload from verifyAccessToken:', payload);

    // Check if user still exists and is active
    console.log('[AuthMiddleware authenticateToken] Fetching user by ID from payload:', payload.userId);
    const user = await UserService.getUserById(payload.userId);
    if (!user) {
      console.log('[AuthMiddleware authenticateToken] User ID:', payload.userId, 'not found or inactive.');
      res.status(401).json({
        success: false,
        message: 'User not found or inactive'
      });
      return;
    }

    // Add user info to request
    req.user = {
      id: user.id,
      username: user.username
    };
    console.log('[AuthMiddleware authenticateToken] User attached to req.user:', req.user);

    next();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('[AuthMiddleware authenticateToken] Error during token authentication:', message);
    res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

/**
 * Optional authentication middleware - doesn't fail if no token
 */
export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  console.log('\n[AuthMiddleware optionalAuth] Checking for token (optional)...');
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    console.log('[AuthMiddleware optionalAuth] Auth header:', authHeader ? 'Present' : 'Missing');
    console.log('[AuthMiddleware optionalAuth] Extracted token (first 10 chars):', token ? token.substring(0, 10) + '...' : 'N/A');

    if (token) {
      const payload: JWTPayload = verifyAccessToken(token);
      console.log('[AuthMiddleware optionalAuth] Token verified (optional). Payload:', payload);
      const user = await UserService.getUserById(payload.userId);
      
      if (user) {
        req.user = {
          id: user.id,
          username: user.username
        };
        console.log('[AuthMiddleware optionalAuth] User attached to req.user (optional):', req.user);
      } else {
        console.log('[AuthMiddleware optionalAuth] User ID:', payload.userId, 'not found or inactive (optional).');
      }
    }

    next();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn('[AuthMiddleware optionalAuth] Error during optional token check (continuing without auth):', message);
    next(); // Continue without authentication in case of error with optional auth
  }
};

/**
 * Middleware to check if user is authenticated
 */
export const requireAuth = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  console.log('\n[AuthMiddleware requireAuth] Checking req.user for protected route...');
  if (!req.user) {
    console.log('[AuthMiddleware requireAuth] req.user is MISSING. Denying access.');
    res.status(401).json({
      success: false,
      message: 'Authentication required'
    });
    return;
  }
  console.log('[AuthMiddleware requireAuth] req.user is PRESENT. Allowing access. User:', req.user);
  next();
}; 