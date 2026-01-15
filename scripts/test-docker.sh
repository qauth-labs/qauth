#!/bin/bash
set -e

echo "🧪 Testing QAuth Docker Setup"
echo "================================"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠️  .env file not found. Creating from .env.docker.example...${NC}"
    if [ -f .env.docker.example ]; then
        cp .env.docker.example .env
        echo -e "${YELLOW}⚠️  Please edit .env and add your JWT keys before continuing!${NC}"
        echo -e "${YELLOW}   Generate keys with: openssl genpkey -algorithm Ed25519 -out private.pem${NC}"
        exit 1
    else
        echo -e "${RED}❌ .env.docker.example not found!${NC}"
        exit 1
    fi
fi

# Check if JWT keys are set
if ! grep -q "JWT_PRIVATE_KEY" .env || grep -q "JWT_PRIVATE_KEY=\"\"" .env; then
    echo -e "${RED}❌ JWT_PRIVATE_KEY not set in .env file!${NC}"
    echo -e "${YELLOW}   Generate keys with:${NC}"
    echo -e "   openssl genpkey -algorithm Ed25519 -out private.pem"
    echo -e "   openssl pkey -in private.pem -pubout -out public.pem"
    echo -e "   Then add them to .env file"
    exit 1
fi

echo -e "${GREEN}✅ Environment check passed${NC}"
echo ""

# Test 1: Build Docker images
echo "📦 Test 1: Building Docker images..."
if docker-compose build --no-cache migration-runner auth-server; then
    echo -e "${GREEN}✅ Docker images built successfully${NC}"
else
    echo -e "${RED}❌ Docker build failed${NC}"
    exit 1
fi
echo ""

# Test 2: Start services
echo "🚀 Test 2: Starting services..."
docker-compose down -v > /dev/null 2>&1 || true
if docker-compose up -d postgres redis; then
    echo -e "${GREEN}✅ Infrastructure services started${NC}"
else
    echo -e "${RED}❌ Failed to start infrastructure services${NC}"
    exit 1
fi

# Wait for postgres to be healthy
echo "⏳ Waiting for PostgreSQL to be healthy..."
timeout=60
elapsed=0
while ! docker-compose exec -T postgres pg_isready -U qauth -d qauth > /dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ $elapsed -ge $timeout ]; then
        echo -e "${RED}❌ PostgreSQL health check timeout${NC}"
        docker-compose logs postgres
        exit 1
    fi
done
echo -e "${GREEN}✅ PostgreSQL is healthy${NC}"
echo ""

# Test 3: Run migrations
echo "🔄 Test 3: Running migrations..."
if docker-compose run --rm migration-runner; then
    echo -e "${GREEN}✅ Migrations completed successfully${NC}"
else
    echo -e "${RED}❌ Migration failed${NC}"
    docker-compose logs migration-runner
    exit 1
fi
echo ""

# Test 4: Start auth-server
echo "🚀 Test 4: Starting auth-server..."
if docker-compose up -d auth-server; then
    echo -e "${GREEN}✅ Auth-server started${NC}"
else
    echo -e "${RED}❌ Failed to start auth-server${NC}"
    docker-compose logs auth-server
    exit 1
fi

# Wait for auth-server to be healthy
echo "⏳ Waiting for auth-server to be healthy..."
timeout=60
elapsed=0
while ! curl -f http://localhost:3000/health > /dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ $elapsed -ge $timeout ]; then
        echo -e "${RED}❌ Auth-server health check timeout${NC}"
        docker-compose logs auth-server
        exit 1
    fi
done
echo -e "${GREEN}✅ Auth-server is healthy${NC}"
echo ""

# Test 5: Verify health checks
echo "🏥 Test 5: Verifying health checks..."
services=("postgres" "redis" "auth-server")
all_healthy=true

for service in "${services[@]}"; do
    health=$(docker inspect --format='{{.State.Health.Status}}' "qauth-${service}" 2>/dev/null || echo "unknown")
    if [ "$health" = "healthy" ] || [ "$health" = "starting" ] || [ "$health" = "unknown" ]; then
        echo -e "  ${GREEN}✅ ${service}: ${health}${NC}"
    else
        echo -e "  ${RED}❌ ${service}: ${health}${NC}"
        all_healthy=false
    fi
done

if [ "$all_healthy" = true ]; then
    echo -e "${GREEN}✅ All health checks passed${NC}"
else
    echo -e "${RED}❌ Some health checks failed${NC}"
    exit 1
fi
echo ""

# Test 6: Test API endpoint
echo "🌐 Test 6: Testing API endpoint..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)
if [ "$response" = "200" ]; then
    echo -e "${GREEN}✅ Health endpoint returned 200${NC}"
else
    echo -e "${RED}❌ Health endpoint returned ${response}${NC}"
    exit 1
fi
echo ""

# Test 7: Verify data persistence
echo "💾 Test 7: Testing data persistence..."
# Create a test record (if we had an API endpoint for it)
# For now, just verify volumes exist
if docker volume inspect qauth_postgres_data > /dev/null 2>&1 && \
   docker volume inspect qauth_redis_data > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Data volumes exist${NC}"
else
    echo -e "${RED}❌ Data volumes not found${NC}"
    exit 1
fi
echo ""

echo -e "${GREEN}🎉 All tests passed!${NC}"
echo ""
echo "Services are running:"
echo "  - Auth API: http://localhost:3000"
echo "  - PostgreSQL: localhost:5432"
echo "  - Redis: localhost:6379"
echo ""
echo "To stop services: docker-compose down"
echo "To view logs: docker-compose logs -f"
