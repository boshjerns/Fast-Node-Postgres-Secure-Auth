import { Router, Request, Response } from 'express';
import { UserService } from '../services/userService';
import { generateTokenPair, verifyRefreshToken } from '../utils/auth';
import { validateRegistration, validateLogin, handleValidationErrors } from '../middleware/validation';
import { authRateLimiter } from '../middleware/security';
import { authenticateToken } from '../middleware/auth';

const router = Router();

// POST /auth/register - Register a new user
router.post('/register', 
  authRateLimiter,
  validateRegistration,
  handleValidationErrors,
  async (req: Request, res: Response): Promise<void> => {
    console.log('\n[Route /auth/register] Received request. Body:', { username: req.body.username, email: req.body.email, password: '***' });
    try {
      const { username, email, password } = req.body;
      const user = await UserService.createUser({ username, email, password });
      console.log('[Route /auth/register] User created:', user);
      const tokens = generateTokenPair(user);

      const refreshTokenExpiry = new Date();
      refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);
      console.log('[Route /auth/register] Storing refresh token for user ID:', user.id, 'Expires:', refreshTokenExpiry);
      await UserService.storeRefreshToken(user.id, tokens.refreshToken, refreshTokenExpiry);

      console.log('[Route /auth/register] Setting refreshToken cookie (first 10 chars):', tokens.refreshToken.substring(0, 10) + '...');
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          user,
          accessToken: tokens.accessToken,
        },
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Registration failed',
      });
    }
  }
);

// POST /auth/login - Authenticate user
router.post('/login',
  authRateLimiter,
  validateLogin,
  handleValidationErrors,
  async (req: Request, res: Response): Promise<void> => {
    console.log('\n[Route /auth/login] Received request. Body:', { username: req.body.username, password: '***' });
    try {
      const { username, password } = req.body;
      const user = await UserService.authenticateUser({ username, password });

      if (!user) {
        console.log('[Route /auth/login] Authentication failed for username:', username);
        res.status(401).json({
          success: false,
          message: 'Invalid username or password',
        });
        return;
      }
      console.log('[Route /auth/login] User authenticated:', user);
      const tokens = generateTokenPair(user);

      const refreshTokenExpiry = new Date();
      refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);
      console.log('[Route /auth/login] Storing refresh token for user ID:', user.id, 'Expires:', refreshTokenExpiry);
      await UserService.storeRefreshToken(user.id, tokens.refreshToken, refreshTokenExpiry);

      console.log('[Route /auth/login] Setting refreshToken cookie (first 10 chars):', tokens.refreshToken.substring(0, 10) + '...');
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user,
          accessToken: tokens.accessToken,
        },
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Login failed',
      });
    }
  }
);

// POST /auth/refresh - Refresh access token
router.post('/refresh', async (req: Request, res: Response): Promise<void> => {
  console.log('\n[Route /auth/refresh] Received request. Cookies:', req.cookies);
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    console.log('[Route /auth/refresh] Attempting to use refresh token (first 10 chars):', refreshToken ? refreshToken.substring(0, 10) + '...' : 'N/A');

    if (!refreshToken) {
      res.status(401).json({
        success: false,
        message: 'Refresh token required',
      });
      return;
    }

    const payload = verifyRefreshToken(refreshToken);
    const storedToken = await UserService.verifyRefreshToken(refreshToken);

    console.log('[Route /auth/refresh] Verifying stored token for hash:', storedToken ? storedToken.token_hash.substring(0,10)+'...' : 'N/A');
    if (!storedToken) {
      console.log('[Route /auth/refresh] Refresh token not found in DB or expired/revoked.');
      res.status(401).json({
        success: false,
        message: 'Invalid or expired refresh token',
      });
      return;
    }

    const user = await UserService.getUserById(payload.userId);
    console.log('[Route /auth/refresh] User found for refresh token:', user);
    if (!user) {
      res.status(401).json({
        success: false,
        message: 'User not found',
      });
      return;
    }

    const tokens = generateTokenPair(user);
    console.log('[Route /auth/refresh] Revoking old refresh token (first 10 chars):', refreshToken.substring(0, 10) + '...');
    await UserService.revokeRefreshToken(refreshToken);
    
    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);
    console.log('[Route /auth/refresh] Storing new refresh token for user ID:', user.id, 'Expires:', refreshTokenExpiry);
    await UserService.storeRefreshToken(user.id, tokens.refreshToken, refreshTokenExpiry);

    console.log('[Route /auth/refresh] Setting new refreshToken cookie (first 10 chars):', tokens.refreshToken.substring(0, 10) + '...');
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken: tokens.accessToken,
      },
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({
      success: false,
      message: 'Token refresh failed',
    });
  }
});

// POST /auth/logout - Logout user
router.post('/logout',
  authenticateToken,
  async (req: Request, res: Response): Promise<void> => {
    console.log('\n[Route /auth/logout] Received request for user:', req.user);
    try {
      const refreshToken = req.cookies.refreshToken;
      if (refreshToken) {
        console.log('[Route /auth/logout] Found refreshToken in cookie. Revoking (first 10 chars):', refreshToken.substring(0, 10) + '...');
        await UserService.revokeRefreshToken(refreshToken);
      } else {
        console.log('[Route /auth/logout] No refreshToken found in cookie.');
      }
      console.log('[Route /auth/logout] Clearing refreshToken cookie.');
      res.clearCookie('refreshToken');
      res.json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Logout failed',
      });
    }
  }
);

// GET /auth/me - Get current user information
router.get('/me',
  authenticateToken,
  async (req: Request, res: Response): Promise<void> => {
    console.log('\n[Route /auth/me] Received request for user:', req.user);
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
        });
        return;
      }

      const user = await UserService.getUserById(req.user.id);
      
      if (!user) {
        res.status(404).json({
          success: false,
          message: 'User not found',
        });
        return;
      }

      console.log('[Route /auth/me] Fetched user details from DB:', user);
      res.json({
        success: true,
        data: { user },
      });
    } catch (error) {
      console.error('Get user error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to get user information',
      });
    }
  }
);

export default router; 