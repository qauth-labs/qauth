#!/bin/sh
set -e

echo "Starting auth server..."
exec tsx src/main.ts
