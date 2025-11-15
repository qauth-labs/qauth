# QAuth Auth Server

The core authentication server for QAuth - a post-quantum ready, headless-first identity platform.

## Overview

This is the main authentication server that provides:

- OAuth 2.1 / OpenID Connect 1.0 endpoints (coming soon)
- RESTful API for authentication
- Session management
- Health check endpoints
- Secure, production-ready configuration

## Features

### ✅ Implemented (P0 - Minimal Setup)

- **Fastify Framework** - Fast, low overhead web framework
- **Security Headers** - Helmet plugin for CSP, HSTS, etc.
- **CORS Support** - Configurable cross-origin resource sharing
- **Database Integration** - PostgreSQL via Drizzle ORM
- **Redis Integration** - Session and cache management
- **Health Checks** - Multiple health check endpoints
- **Environment Config** - Type-safe environment variable handling
- **Logging** - Pino logger with pretty printing in development
- **Graceful Shutdown** - Proper cleanup of connections

### 🚧 Coming Soon

- OAuth 2.1 authorization flows
- OIDC 1.0 implementation
- User authentication (email/password)
- JWT token management
- Role-based access control

## Prerequisites

Before running the auth server, ensure you have:

1. **Node.js** >= 24.0.0
2. **pnpm** >= 10.0.0
3. **PostgreSQL** >= 14
4. **Redis** >= 6

## Quick Start

### 1. Environment Setup

Copy the example environment file:

```bash
cp apps/auth-server/.env.example apps/auth-server/.env
```

Edit `.env` and configure your database and Redis connections:

```env
# Server
NODE_ENV=development
HOST=localhost
PORT=3000

# Database
DATABASE_URL=postgresql://qauth:qauth@localhost:5432/qauth

# Redis
REDIS_URL=redis://localhost:6379
```

### 2. Install Dependencies

From the workspace root:

```bash
pnpm install
```

### 3. Build the Server

```bash
pnpm nx build auth-server
```

### 4. Run the Server

Development mode with hot reload:

```bash
pnpm nx serve auth-server
```

The server will start at `http://localhost:3000`

## API Endpoints

### Health Checks

- `GET /health` - Basic health check (returns 200 if server is up)
- `GET /health/detailed` - Detailed health with DB and Redis status
- `GET /.well-known/health` - RFC 5785 standard health endpoint

### Information

- `GET /` - API information and available endpoints

### Example Response

```bash
curl http://localhost:3000/

{
  "name": "QAuth Auth Server",
  "description": "Post-quantum ready, headless-first identity platform",
  "version": "0.0.0",
  "status": "development",
  "endpoints": {
    "health": "/health",
    "detailedHealth": "/health/detailed",
    "wellKnown": "/.well-known/health"
  },
  "documentation": "https://docs.qauth.dev"
}
```

## Project Structure

```
apps/auth-server/
├── src/
│   ├── main.ts                    # Application entry point
│   ├── app/
│   │   ├── app.ts                 # Fastify app configuration
│   │   ├── plugins/               # Fastify plugins
│   │   │   ├── sensible.ts        # HTTP error utilities
│   │   │   ├── cors.ts            # CORS configuration
│   │   │   ├── helmet.ts          # Security headers
│   │   │   ├── env.ts             # Environment validation
│   │   │   ├── database.ts        # Database connection
│   │   │   └── redis.ts           # Redis connection
│   │   └── routes/                # Route handlers
│   │       ├── root.ts            # API info endpoint
│   │       └── health.ts          # Health check endpoints
├── .env.example                   # Example environment variables
└── project.json                   # Nx project configuration
```

## Configuration

### Environment Variables

| Variable       | Description                          | Default                                         |
| -------------- | ------------------------------------ | ----------------------------------------------- |
| `NODE_ENV`     | Environment (development/production) | `development`                                   |
| `HOST`         | Server host                          | `localhost`                                     |
| `PORT`         | Server port                          | `3000`                                          |
| `DATABASE_URL` | PostgreSQL connection string         | `postgresql://qauth:qauth@localhost:5432/qauth` |
| `REDIS_URL`    | Redis connection string              | `redis://localhost:6379`                        |
| `CORS_ORIGIN`  | Allowed CORS origins                 | `*`                                             |

### Logging

The server uses Pino for logging:

- **Development**: Pretty-printed logs with timestamps
- **Production**: JSON logs for structured logging

### Security

Security features enabled by default:

- **Helmet**: Security headers (CSP, HSTS, X-Frame-Options, etc.)
- **CORS**: Configurable cross-origin resource sharing
- **Request ID**: Unique ID for each request (via `x-request-id` header)
- **Graceful Shutdown**: Proper cleanup on SIGTERM/SIGINT

## Development

### Run Linting

```bash
pnpm nx lint auth-server
```

### Run Type Checking

```bash
pnpm nx typecheck auth-server
```

### Build for Production

```bash
pnpm nx build auth-server --configuration=production
```

## Deployment

### Docker (Coming Soon)

```bash
docker build -t qauth-auth-server .
docker run -p 3000:3000 --env-file .env qauth-auth-server
```

### Kubernetes (Coming Soon)

See deployment manifests in `/deploy` directory.

## Troubleshooting

### Database Connection Failed

Ensure PostgreSQL is running and the `DATABASE_URL` is correct:

```bash
# Check PostgreSQL status
psql $DATABASE_URL -c "SELECT 1"
```

### Redis Connection Failed

Ensure Redis is running and the `REDIS_URL` is correct:

```bash
# Check Redis status
redis-cli -u $REDIS_URL ping
```

### Port Already in Use

Change the `PORT` in `.env` or use:

```bash
PORT=3001 pnpm nx serve auth-server
```

## Contributing

See the [main CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution guidelines.

## License

Apache 2.0 - see [LICENSE](../../LICENSE)

---

**Status**: Development (P0 Complete)
**Next Phase**: OAuth 2.1 implementation
