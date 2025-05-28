# Secure Authentication Application

A robust Node.js application demonstrating secure user authentication and session management using PostgreSQL for data storage, JWTs (Access and Refresh Tokens) for authorization, password hashing with bcrypt, and HTTPS support. Includes detailed logging for understanding the authentication flow.

## Features

- 🔐 **Secure User Authentication**: JWT-based with distinct Access and Refresh Tokens.
- 🍪 **HttpOnly Cookies**: Refresh Tokens are stored in secure `HttpOnly` cookies.
- 🔑 **Token Management**: Access Token in response, Refresh Token in cookie. Includes `/api/auth/refresh` endpoint.
- 🛡️ **Password Security**: `bcrypt` hashing for passwords (configurable rounds).
- 🗄️ **PostgreSQL Database**: For storing users and refresh token hashes.
- 📜 **Database Migrations**: Simple script to initialize database tables (`users`, `refresh_tokens`).
- 🔒 **HTTPS Support**: With self-signed certificate generation for development and HTTP to HTTPS redirection in production mode.
- 🚦 **Rate Limiting**: Protects against brute-force attacks on authentication and general API routes.
- 🛡️ **Security Headers**: `helmet` for various HTTP security enhancements, including Content Security Policy.
- ✅ **Input Validation**: Server-side validation for registration and login using `express-validator`.
- 🔄 **Account Lockout**: Temporarily locks accounts after multiple failed login attempts.
- 📝 **Detailed Logging**: Extensive console logging on both backend and frontend for tracing requests, auth processes, and errors.
- 🖥️ **Simple Frontend**: Basic HTML/CSS/JS frontend for testing registration, login, and logout.
- ⚙️ **TypeScript & Express.js**: Modern and robust backend stack.
- 🛠️ **Development Workflow**: `nodemon` for auto-reloading, `ts-node` for running TypeScript directly.

## Prerequisites

- Node.js (v16 or higher recommended)
- PostgreSQL (v12 or higher recommended)
- OpenSSL (for generating SSL certificates for HTTPS development testing)
- An API testing tool like Postman or curl (optional, for backend testing).

## Local Setup Instructions

**1. Clone the Repository:**
```bash
git clone <your-repository-url>
cd secure-auth-app
```

**2. Install Dependencies:**
```bash
npm install
```

**3. Setup PostgreSQL Database:**
   a. **Connect to your PostgreSQL instance** (e.g., using `psql` or a GUI tool like pgAdmin).
      If using `psql` and your main PostgreSQL user is `postgres`:
      ```bash
      psql -U postgres
      ```
      (You might be prompted for the `postgres` user's password).

   b. **Create the database and a dedicated user for the application.** For easy testing, we'll use `testuser` and `testpass`. **Replace these with strong, unique credentials for production.**
      Execute the following SQL commands:
      ```sql
      CREATE DATABASE secure_auth_db;
      CREATE USER testuser WITH PASSWORD 'testpass';
      GRANT ALL PRIVILEGES ON DATABASE secure_auth_db TO testuser;
      -- Connect to the new database to grant schema permissions (important!)
      \c secure_auth_db 
      GRANT ALL ON SCHEMA public TO testuser;
      ```
      *Note: If the `\c secure_auth_db` command gives an error within a script, you might need to connect to `secure_auth_db` with `testuser` and then run `GRANT ALL ON SCHEMA public TO testuser;` separately. The `setup_db.sql` script provided in the root handles this.* 
      Alternatively, you can run the provided setup script (after ensuring your `postgres` user can connect without a password prompt locally or by setting `PGPASSWORD`):
      ```bash
      # Make sure psql is in your PATH or provide the full path to psql.exe
      # Example for default PostgreSQL 16 on Windows, adjust if needed:
      # $env:PGPASSWORD="your_postgres_superuser_password"; & "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -f setup_db.sql
      psql -U postgres -f setup_db.sql 
      ```

**4. Configure Environment Variables:**
   a. Copy the example environment file:
      ```bash
      cp env.example .env
      ```
   b. Edit the `.env` file with your actual database credentials and generate strong JWT secrets:
      ```env
      # Database Configuration
      DB_HOST=localhost
      DB_PORT=5432
      DB_NAME=secure_auth_db
      DB_USER=testuser       # The user you created in step 3b
      DB_PASSWORD=testpass   # The password for testuser

      # JWT Configuration (IMPORTANT: Generate strong, unique random strings for production!)
      JWT_SECRET=your_very_long_and_random_access_token_secret_here_32_chars_plus
      JWT_EXPIRES_IN=24h
      JWT_REFRESH_SECRET=another_very_long_and_random_refresh_token_secret_here_32_chars_plus

      # Server Configuration
      PORT=3000
      HTTPS_PORT=3443
      NODE_ENV=development # Set to 'production' for production builds

      # SSL Certificate paths (for HTTPS)
      SSL_KEY_PATH=./certs/private-key.pem
      SSL_CERT_PATH=./certs/certificate.pem

      # Security Configuration
      BCRYPT_ROUNDS=12
      RATE_LIMIT_WINDOW_MS=300000   # 5 minutes for development (auth routes)
      RATE_LIMIT_MAX_REQUESTS=100 # Increased for development (auth routes)

      # CORS Configuration (add your frontend production domain here)
      ALLOWED_ORIGINS=http://localhost:3000,https://localhost:3443
      ```

**5. Build TypeScript & Initialize Database Schema:**
   The application will attempt to create tables on startup if they don't exist, driven by `src/database/migrate.ts` which is called by `src/server.ts`.
   First, build the TypeScript:
   ```bash
   npm run build
   ```
   The database tables (`users`, `refresh_tokens`) should be created automatically when the server starts if they don't exist. You can also run the migration script manually if needed (e.g., after schema changes):
   ```bash
   npm run db:migrate
   ```

**6. Generate SSL Certificates (Optional, for local HTTPS testing):**
   If you want to test HTTPS locally:
   ```bash
   npm run generate-certs
   ```
   Then, to enable HTTPS mode, set `NODE_ENV=production` in your `.env` file and restart the server. Your browser will show a warning for self-signed certificates.

**7. Start the Development Server:**
   ```bash
   npm run dev
   ```
   The application will be available at `http://localhost:3000`.
   The API will be at `http://localhost:3000/api`.
   You should see extensive logging in your terminal.

## Application Architecture & Auth Flow (Mermaid)

```mermaid
sequenceDiagram
    %% Apply a base theme for better styling
    %%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '13px', 'sequenceParticipantFontSize': '14px', 'sequenceNoteFontSize': '13px'}}}%%

    participant Client as Browser
    participant Server as Node.js/Express
    participant Database as PostgreSQL

    rect rgb(230, 240, 255) // Light Blue for Registration
        Client->>Server: POST /api/auth/register (username, email, password)
        Server->>Server: Validate input
        alt Validation Fails
            Server-->>Client: 400 Bad Request (validation errors)
        else Validation Succeeds
            Server->>Server: Hash password (bcrypt)
            Server->>Database: INSERT user (username, email, password_hash)
            Database-->>Server: User created (id, etc.)
            Server->>Server: Generate Access Token (short-lived)
            Server->>Server: Generate Refresh Token (long-lived)
            Server->>Database: Store Refresh Token hash (linked to user_id)
            Server-->>Client: 201 Created (User data, Access Token in body, Refresh Token in HttpOnly Cookie)
            Client->>Client: Store Access Token (localStorage)
        end
    end

    rect rgb(230, 255, 230) // Light Green for Login
        Client->>Server: POST /api/auth/login (username, password)
        Server->>Server: Validate input
        Server->>Database: SELECT user by username
        alt User Not Found or Inactive
            Server-->>Client: 401 Unauthorized
        else User Found
            Server->>Server: Compare submitted password with stored hash (bcrypt.compare)
            alt Password Mismatch
                Server->>Database: Increment failed_login_attempts
                Server-->>Client: 401 Unauthorized
            else Password Match
                Server->>Database: Reset failed_login_attempts, update last_login
                Server->>Server: Generate Access Token
                Server->>Server: Generate Refresh Token
                Server->>Database: Store new Refresh Token hash
                Server-->>Client: 200 OK (User data, Access Token in body, Refresh Token in HttpOnly Cookie)
                Client->>Client: Store Access Token (localStorage)
            end
        end
    end

    rect rgb(255, 245, 230) // Light Orange for Protected Route Access
        Client->>Server: GET /api/auth/me (Header: Authorization: Bearer <AccessToken>)
        Server->>Server: Middleware: authenticateToken verifies Access Token
        alt Access Token Invalid/Expired
            Server-->>Client: 401 Unauthorized (Client should then attempt /refresh)
        else Access Token Valid
            Server->>Database: Fetch user details by user_id from token
            Server-->>Client: 200 OK (user details)
        end
    end

    rect rgb(255, 230, 230) // Light Red for Token Refresh
        Client->>Server: POST /api/auth/refresh (Cookie: refreshToken=<RefreshTokenValue>)
        Server->>Server: Verify Refresh Token (check hash in DB, expiry, revocation)
        alt Refresh Token Invalid/Expired
            Server-->>Client: 401 Unauthorized (User must log in again)
        else Refresh Token Valid
            Server->>Server: Generate new Access Token
            Server->>Server: (Optional: Generate new Refresh Token & update cookie)
            Server->>Database: Revoke old Refresh Token, Store new one (if rolling)
            Server-->>Client: 200 OK (New Access Token in body)
            Client->>Client: Update stored Access Token
        end
    end

    rect rgb(240, 240, 240) // Light Grey for Logout
        Client->>Server: POST /api/auth/logout (Header: Authorization: Bearer <AccessToken>)
        Server->>Server: Middleware: authenticateToken (identifies user)
        Server->>Database: Revoke Refresh Token from DB (associated with cookie/user)
        Server-->>Client: 200 OK (Clear refreshToken cookie)
        Client->>Client: Remove Access Token from localStorage
        Client->>Client: Show Login/Register UI
    end
```

## API Endpoints

Base URL: `http://localhost:3000/api` (or HTTPS equivalent)

### Authentication (`/auth`)

-   **`POST /register`**: Register a new user.
    -   Body: `{ "username": "string", "email": "string", "password": "string" }`
    -   Response (201): User object, access token, refresh token in cookie.
-   **`POST /login`**: Log in an existing user.
    -   Body: `{ "username": "string", "password": "string" }`
    -   Response (200): User object, access token, refresh token in cookie.
-   **`POST /logout`**: Log out the current user.
    -   Requires `Authorization: Bearer <accessToken>` header.
    -   Response (200): Success message, clears refresh token cookie.
-   **`POST /refresh`**: Obtain a new access token using a refresh token.
    -   Uses `refreshToken` from `HttpOnly` cookie.
    -   Response (200): New access token.
-   **`GET /me`**: Get details of the currently authenticated user.
    -   Requires `Authorization: Bearer <accessToken>` header.
    -   Response (200): User object.

### Other

-   **`GET /health`**: Health check endpoint for the server.
-   **`GET /api/protected`**: Example protected route, requires authentication.

## Key Security Features Implemented

-   **Password Hashing**: `bcrypt` (12 rounds).
-   **JWTs**: Access (24hr expiry) and Refresh (7day expiry) tokens.
-   **HttpOnly Cookies**: For refresh tokens.
-   **Secure Cookie Flags**: `secure` (in prod) and `sameSite='strict'`.
-   **Rate Limiting**: On auth and general routes.
-   **Account Lockout**: After 5 failed login attempts (30 min lockout).
-   **Input Validation**: For registration and login.
-   **Helmet**: For various security HTTP headers (CSP, XSS protection, etc.).
-   **CORS**: Configured to allow specific origins.
-   **HTTPS**: Supported, with HTTP to HTTPS redirection in production.

## Key Dependencies (from package.json)

-   **`express`**: Fast, unopinionated, minimalist web framework for Node.js.
-   **`pg`**: Non-blocking PostgreSQL client for Node.js. Used for database interaction.
-   **`bcryptjs`**: Library for hashing passwords securely.
-   **`jsonwebtoken`**: Library to generate and verify JSON Web Tokens (JWTs).
-   **`cors`**: Express middleware for enabling Cross-Origin Resource Sharing.
-   **`helmet`**: Express middleware for setting various HTTP security headers.
-   **`express-rate-limit`**: Express middleware for basic rate-limiting to protect against brute-force attacks.
-   **`express-validator`**: Express middleware for server-side data validation.
-   **`dotenv`**: Loads environment variables from a `.env` file into `process.env`.
-   **`cookie-parser`**: Express middleware for parsing `Cookie` header and populating `req.cookies`.

## Key Dev Dependencies (from package.json)

-   **`typescript`**: Superset of JavaScript that adds static types.
-   **`ts-node`**: TypeScript execution environment for Node.js, allows running TS files directly.
-   **`nodemon`**: Utility that monitors for changes in your source and automatically restarts the server.
-   **`@types/*`**: Various type definition packages for libraries that don't include their own (e.g., `@types/express`, `@types/pg`, `@types/bcryptjs`, etc.), enabling better TypeScript support and autocompletion.

## Project Structure

```
secure-auth-app/
├── certs/                   # (Generated) SSL certificates
├── dist/                    # (Generated) Compiled JavaScript output
├── node_modules/            # NPM dependencies
├── public/                  # Static frontend files
│   └── index.html           # Simple HTML frontend
├── scripts/
│   └── generate-certs.js    # Script to generate SSL certs
├── src/
│   ├── config/
│   │   └── database.ts      # PostgreSQL connection setup
│   │   
│   ├── database/
│   │   └── migrate.ts       # Database schema migration script
│   ├── middleware/
│   │   ├── auth.ts          # JWT authentication middleware
│   │   ├── security.ts      # Helmet, CORS, rate limiting
│   │   └── validation.ts    # express-validator rules
│   ├── models/
│   │   └── User.ts          # TypeScript interfaces for User, Tokens etc.
│   ├── routes/
│   │   └── auth.ts          # Authentication API routes
│   ├── services/
│   │   └── userService.ts   # Business logic for user operations
│   ├── utils/
│   │   └── auth.ts          # JWT and password hashing utilities
│   └── server.ts            # Express server setup, main application file
├── .env                     # Local environment variables (Gitignored)
├── .env.example             # Example environment variables
├── .gitignore               # Files and directories to ignore in Git
├── nodemon.json             # Nodemon configuration
├── package-lock.json
├── package.json
├── README.md                # This file
├── setup_db.sql             # SQL script to setup database and user
└── tsconfig.json            # TypeScript compiler options
```

## Environment Variables

Refer to `.env.example` for a full list and descriptions. Key variables include database connection details, JWT secrets, server ports, and `NODE_ENV`.

## Development Scripts

-   `npm run dev`: Starts the development server using `nodemon` and `ts-node` (with hot-reloading).
-   `npm run build`: Compiles TypeScript to JavaScript (output to `dist/`).
-   `npm start`: Runs the compiled JavaScript application (from `dist/`). Useful for production-like testing.
-   `npm run db:migrate`: Executes the database migration script (`dist/database/migrate.js`).
-   `npm run generate-certs`: Generates self-signed SSL certificates for local HTTPS.

## Production Considerations

-   **Use strong, unique secrets** for `JWT_SECRET`, `JWT_REFRESH_SECRET`, and database passwords. Store them securely (e.g., environment variables in your hosting provider, secrets manager).
-   Set `NODE_ENV=production`.
-   **Use valid SSL certificates** from a trusted Certificate Authority for HTTPS.
-   Configure `ALLOWED_ORIGINS` in `.env` for your production frontend domain(s).
-   Review and tighten rate limits.
-   Implement robust logging and monitoring for the production environment.
-   Consider a more advanced database migration tool (e.g., Knex.js) for complex schema evolution.
-   Ensure database backups are regularly performed.

---

This application serves as a comprehensive template for building secure Node.js applications with robust authentication. Remember to replace placeholder secrets and adapt configurations for production use. 