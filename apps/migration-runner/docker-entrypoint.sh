#!/bin/sh
set -e

echo "Running database migrations using Nx..."
# Run migrations using Nx target from infra-db
# This uses the proper Nx workflow and respects project boundaries
pnpm nx run infra-db:db:migrate

echo "Migrations completed successfully"
