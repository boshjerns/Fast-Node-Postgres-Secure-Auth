import express from 'express';
import https from 'https';
import http from 'http';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import cors from 'cors';

// Import middleware
import { helmetConfig, corsOptions, generalRateLimiter, requestLogger, errorHandler, notFoundHandler } from './middleware/security';
import { authenticateToken } from './middleware/auth';

// Import routes
import authRoutes from './routes/auth';

// Import database migration
import { createUsersTable } from './database/migrate';

// Load environment variables
dotenv.config();

const app = express();
const PORT = parseInt(process.env.PORT || '3000');
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT || '3443');

// Trust proxy for rate limiting behind reverse proxy
app.set('trust proxy', 1);

// Security middleware
app.use(helmetConfig);
app.use(cors(corsOptions));
app.use(generalRateLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Request logging
app.use(requestLogger);

// Serve static files
app.use(express.static(path.join(__dirname, '../public')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// API routes
app.use('/api/auth', authRoutes);

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'This is a protected route',
    user: req.user
  });
});

// 404 handler
app.use(notFoundHandler);

// Error handling middleware
app.use(errorHandler);

// Function to start HTTP server
const startHttpServer = (): void => {
  const httpServer = http.createServer(app);
  
  httpServer.listen(PORT, () => {
    console.log(`HTTP Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
};

// Function to start HTTPS server
const startHttpsServer = (): void => {
  try {
    const sslKeyPath = process.env.SSL_KEY_PATH || './certs/private-key.pem';
    const sslCertPath = process.env.SSL_CERT_PATH || './certs/certificate.pem';

    // Check if SSL certificates exist
    if (!fs.existsSync(sslKeyPath) || !fs.existsSync(sslCertPath)) {
      console.log('SSL certificates not found. Starting HTTP server only.');
      console.log('To enable HTTPS, generate SSL certificates and update the paths in your .env file.');
      startHttpServer();
      return;
    }

    const httpsOptions = {
      key: fs.readFileSync(sslKeyPath),
      cert: fs.readFileSync(sslCertPath),
    };

    const httpsServer = https.createServer(httpsOptions, app);

    httpsServer.listen(HTTPS_PORT, () => {
      console.log(`HTTPS Server running on port ${HTTPS_PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });

    // Also start HTTP server for redirects
    const httpApp = express();
    httpApp.use((req, res) => {
      res.redirect(301, `https://${req.headers.host?.replace(PORT.toString(), HTTPS_PORT.toString())}${req.url}`);
    });

    httpApp.listen(PORT, () => {
      console.log(`HTTP Server running on port ${PORT} (redirecting to HTTPS)`);
    });

  } catch (error) {
    console.error('Error starting HTTPS server:', error);
    console.log('Falling back to HTTP server...');
    startHttpServer();
  }
};

// Initialize database and start server
const initializeApp = async (): Promise<void> => {
  try {
    console.log('Initializing database...');
    await createUsersTable();
    console.log('Database initialized successfully');

    // Start server based on environment
    if (process.env.NODE_ENV === 'production') {
      startHttpsServer();
    } else {
      console.log('Development mode: Starting HTTP server');
      startHttpServer();
    }

  } catch (error) {
    console.error('Failed to initialize application:', error);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

// Start the application
initializeApp();

export default app; 