# QAuth Development Guide

This guide covers the development setup, common commands, and troubleshooting for the QAuth OAuth 2.1/OIDC server.

## Prerequisites

Before starting development, ensure you have the following installed:

- **Node.js**: Version 24.0.0 or higher
- **pnpm**: Version 10.0.0 or higher (recommended package manager)
- **Docker**: Version 20.10+ with Docker Compose
- **Git**: Latest version

### Verification

```bash
# Check Node.js version
node --version  # Should be >= 24.0.0

# Check pnpm version
pnpm --version  # Should be >= 10.0.0

# Check Docker
docker --version
docker-compose --version
```

## Quick Start

1. **Clone the repository**

   ```bash
   git clone https://github.com/qauth-labs/qauth.git
   cd qauth
   ```

2. **Install dependencies**

   ```bash
   pnpm install
   ```

3. **Set up environment**

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start infrastructure services**

   ```bash
   make docker-up
   # or
   docker-compose up -d
   ```

5. **Set up database**

   ```bash
   make db-generate  # Generate migrations
   make db-push      # Apply schema to database
   ```

6. **Start development server**

   ```bash
   make dev
   # or
   pnpm nx serve auth-server
   ```

7. **Verify setup**
   ```bash
   make health
   ```

The server should now be running at `http://localhost:3000`.

## Project Structure

```
qauth/
├── apps/
│   └── auth-server/           # Main OAuth 2.1/OIDC server application
│       ├── src/
│       │   ├── app/          # Fastify application setup
│       │   ├── config/       # Environment configuration
│       │   └── main.ts       # Application entry point
├── libs/
│   ├── data-access/
│   │   ├── db/              # Database client and schemas
│   │   └── redis/           # Redis client and session management
│   └── shared/
│       ├── constants/       # Application constants
│       ├── types/          # TypeScript type definitions
│       └── utils/          # Utility functions
├── docker-compose.yml      # Development infrastructure
├── drizzle.config.ts      # Database migration configuration
└── docs/                  # Documentation
```

## Common Commands

### Development

```bash
# Start development server with hot reload
make dev

# Build all projects
make build

# Run linting
make lint

# Format code
make format

# Run tests
make test
```

### Database

```bash
# Generate migrations from schema changes
make db-generate

# Apply migrations to database
make db-migrate

# Push schema directly (development only)
make db-push

# Open Drizzle Studio (database GUI)
make db-studio
```

### Docker Services

```bash
# Start PostgreSQL and Redis
make docker-up

# Stop services
make docker-down

# View logs
make docker-logs

# Restart services
make docker-restart

# Clean up (removes data)
make docker-clean
```

### Development Tools

```bash
# Start Redis Commander and pgAdmin
make tools-up

# Stop development tools
make tools-down

# Access Redis Commander: http://localhost:8081
# Access pgAdmin: http://localhost:8080
```

## Environment Configuration

The application uses environment variables for configuration. Copy `.env.example` to `.env` and modify as needed:

### Required Variables

```bash
# Database
DATABASE_URL=postgresql://qauth:qauth@localhost:5432/qauth_dev

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT Secret (minimum 32 characters)
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long
```

### Optional Variables

```bash
# Server
PORT=3000
NODE_ENV=development
LOG_LEVEL=debug

# CORS
CORS_ORIGIN=
CORS_CREDENTIALS=true

# Security
RATE_LIMIT_ENABLED=true
SESSION_SECURE=false
```

## API Endpoints

### Health Checks

- `GET /health` - Basic health check
- `GET /health/detailed` - Detailed health information
- `GET /status` - Lightweight status check

### Service Information

- `GET /` - Service information and available endpoints
- `GET /version` - Version information

## Architecture Overview

### OAuth 2.1/OIDC Compliance

- **PKCE (Proof Key for Code Exchange)**: Mandatory for all authorization flows
- **Short-lived tokens**: Access tokens expire in 15 minutes
- **Secure refresh tokens**: 7-day expiration with revocation support
- **Session management**: Redis-backed with automatic cleanup

### Security Features

- **Argon2id password hashing**: Post-quantum secure
- **JWT tokens**: Signed with configurable secrets
- **Rate limiting**: Configurable per endpoint
- **CORS protection**: Configurable origins
- **Security headers**: Helmet.js integration

### Database Design

- **PostgreSQL**: Primary database with connection pooling
- **Redis**: Session storage and caching
- **Drizzle ORM**: Type-safe database operations
- **Migrations**: Version-controlled schema changes

## Troubleshooting

### Common Issues

#### Server Won't Start

```bash
# Check if port is already in use
lsof -i :3000

# Check environment variables
cat .env

# Check database connection
make health
```

#### Database Connection Issues

```bash
# Check PostgreSQL status
docker-compose ps postgres

# Check PostgreSQL logs
docker-compose logs postgres

# Test connection manually
docker-compose exec postgres psql -U qauth -d qauth_dev -c "SELECT 1;"
```

#### Redis Connection Issues

```bash
# Check Redis status
docker-compose ps redis

# Check Redis logs
docker-compose logs redis

# Test connection manually
docker-compose exec redis redis-cli ping
```

#### Migration Issues

```bash
# Reset database (WARNING: deletes all data)
make docker-clean
make docker-up
make db-push

# Check migration status
make db-studio
```

### Performance Issues

#### Database Performance

```bash
# Check connection pool status
curl -s http://localhost:3000/health/detailed | jq '.dependencies.database'

# Monitor PostgreSQL
docker-compose exec postgres psql -U qauth -d qauth_dev -c "SELECT * FROM pg_stat_activity;"
```

#### Redis Performance

```bash
# Check Redis memory usage
curl -s http://localhost:3000/health/detailed | jq '.dependencies.redis'

# Monitor Redis
docker-compose exec redis redis-cli info memory
```

### Development Tips

1. **Use development tools**: Enable Redis Commander and pgAdmin for easier debugging
2. **Monitor logs**: Use `make docker-logs` to see real-time service logs
3. **Database GUI**: Use `make db-studio` for visual database management
4. **Health checks**: Use `make health` to verify service status
5. **Environment validation**: The server will fail fast with clear error messages for invalid environment variables

## Contributing

1. **Code style**: Use Prettier and ESLint (run `make format` and `make lint`)
2. **Type safety**: Maintain strict TypeScript configuration
3. **Testing**: Write tests for new features
4. **Documentation**: Update this guide for significant changes
5. **Security**: Follow OAuth 2.1/OIDC best practices

## Next Steps

After completing the development setup:

1. **Phase 1**: Implement OAuth 2.1 authorization flows
2. **Phase 2**: Add OIDC support and user management
3. **Phase 3**: Build developer portal
4. **Phase 4**: Add post-quantum cryptography
5. **Phase 5**: Implement advanced security features

For more information, see the [MVP Roadmap](../MVP-PRD.md).
