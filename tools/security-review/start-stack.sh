#!/usr/bin/env bash
# Start a local QAuth stack inside the security-review image, with no network.
#
#   tools/security-review/start-stack.sh           start it and leave it running
#   tools/security-review/start-stack.sh --check   start it, wait for /health, stop it,
#                                                  and exit 0 if it was healthy, 1 if not
#
# It starts PostgreSQL 18 and Redis on localhost, creates the `qauth` database,
# generates a throwaway EdDSA signing key, runs the migrations and starts the
# auth-server on http://localhost:3000. Logs go to $STATE_DIR.
#
# Every variable below is a default. Export your own value first to override
# it, for example to turn on a default-off surface:
#
#   WALLET_FEDERATION_ENABLED=true tools/security-review/start-stack.sh
#
# Throwaway by design: the key, the session secret and the database password
# exist only for this container. Never point this script at real data.

set -euo pipefail

MODE="${1:-start}"
case "$MODE" in
  start | --check) ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/node_modules/.bin"
STATE_DIR="${STATE_DIR:-/tmp/qauth-review}"
PG_VERSION=18
DB_PASSWORD='qauth_review_only'
mkdir -p "$STATE_DIR"

log() { printf '[start-stack] %s\n' "$*"; }

# --- PostgreSQL --------------------------------------------------------------
# grep without -q reads all of its input, so `pipefail` never sees a SIGPIPE.
if ! pg_lsclusters --no-header | awk '{print $1, $2}' | grep -x "$PG_VERSION main" >/dev/null; then
  pg_createcluster "$PG_VERSION" main >/dev/null
fi
if ! pg_isready -q -h 127.0.0.1 -p 5432; then
  log "starting PostgreSQL $PG_VERSION"
  pg_ctlcluster "$PG_VERSION" main start
fi
for _ in $(seq 1 30); do
  pg_isready -q -h 127.0.0.1 -p 5432 && break
  sleep 1
done
pg_isready -q -h 127.0.0.1 -p 5432 || {
  echo "PostgreSQL did not become ready" >&2
  exit 1
}

psql_admin() { runuser -u postgres -- psql -v ON_ERROR_STOP=1 -tAq "$@"; }
if [ -z "$(psql_admin -c "SELECT 1 FROM pg_roles WHERE rolname = 'qauth'")" ]; then
  psql_admin -c "CREATE ROLE qauth LOGIN PASSWORD '$DB_PASSWORD'"
fi
if [ -z "$(psql_admin -c "SELECT 1 FROM pg_database WHERE datname = 'qauth'")" ]; then
  psql_admin -c "CREATE DATABASE qauth OWNER qauth"
fi

# --- Redis -------------------------------------------------------------------
if ! redis-cli -h 127.0.0.1 -p 6379 ping >/dev/null 2>&1; then
  log "starting Redis"
  redis-server --bind 127.0.0.1 --port 6379 --save '' --appendonly no \
    --daemonize yes --logfile "$STATE_DIR/redis.log"
fi
for _ in $(seq 1 30); do
  redis-cli -h 127.0.0.1 -p 6379 ping >/dev/null 2>&1 && break
  sleep 1
done

# --- Throwaway signing key and secrets ---------------------------------------
if [ ! -f "$STATE_DIR/jwt-private.pem" ]; then
  node -e '
    const { generateKeyPairSync } = require("node:crypto");
    const { writeFileSync } = require("node:fs");
    const dir = process.argv[1];
    const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    writeFileSync(dir + "/jwt-private.pem", privateKey, { mode: 0o600 });
    writeFileSync(dir + "/jwt-public.pem", publicKey);
  ' "$STATE_DIR"
fi
if [ ! -f "$STATE_DIR/session-secret" ]; then
  node -e 'process.stdout.write(require("node:crypto").randomBytes(48).toString("base64"))' \
    >"$STATE_DIR/session-secret"
fi

# --- Environment (the same minimum the CI container smoke test boots with) ---
: "${NODE_ENV:=production}"
: "${HOST:=127.0.0.1}"
: "${PORT:=3000}"
: "${LOG_LEVEL:=info}"
: "${DATABASE_URL:=postgresql://qauth:${DB_PASSWORD}@127.0.0.1:5432/qauth}"
: "${REDIS_URL:=redis://127.0.0.1:6379/0}"
: "${REDIS_HOST:=127.0.0.1}"
: "${REDIS_PORT:=6379}"
: "${JWT_PRIVATE_KEY:=$(cat "$STATE_DIR/jwt-private.pem")}"
: "${JWT_PUBLIC_KEY:=$(cat "$STATE_DIR/jwt-public.pem")}"
: "${JWT_ISSUER:=http://localhost:${PORT}}"
: "${SESSION_COOKIE_SECRET:=$(cat "$STATE_DIR/session-secret")}"
: "${SESSION_COOKIE_SECURE:=false}"
: "${EMAIL_PROVIDER:=mock}"
: "${EMAIL_FROM_ADDRESS:=noreply@example.test}"
: "${EMAIL_BASE_URL:=http://localhost:${PORT}}"
export NODE_ENV HOST PORT LOG_LEVEL DATABASE_URL REDIS_URL REDIS_HOST REDIS_PORT \
  JWT_PRIVATE_KEY JWT_PUBLIC_KEY JWT_ISSUER SESSION_COOKIE_SECRET SESSION_COOKIE_SECURE \
  EMAIL_PROVIDER EMAIL_FROM_ADDRESS EMAIL_BASE_URL

# --- Migrations, the way the migration-runner image applies them -------------
log "applying migrations"
(cd "$ROOT/libs/infra/db" && "$BIN/drizzle-kit" migrate) >"$STATE_DIR/migrate.log" 2>&1 || {
  cat "$STATE_DIR/migrate.log" >&2
  echo "migrations failed" >&2
  exit 1
}

# --- auth-server, the way its production image runs it -----------------------
log "starting auth-server on http://localhost:${PORT}"
(
  cd "$ROOT/apps/auth-server"
  nohup "$BIN/tsx" src/main.ts >"$STATE_DIR/auth-server.log" 2>&1 &
  echo $! >"$STATE_DIR/auth-server.pid"
)

healthy=false
for _ in $(seq 1 90); do
  body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/health" 2>/dev/null || true)"
  case "$body" in
    *'"status":"ok"'*)
      healthy=true
      break
      ;;
  esac
  sleep 1
done

if [ "$healthy" != true ]; then
  echo "auth-server did not report healthy. Last log lines:" >&2
  tail -n 60 "$STATE_DIR/auth-server.log" >&2 || true
  exit 1
fi

log "auth-server is healthy: $body"

if [ "$MODE" = --check ]; then
  # A check leaves nothing running behind it.
  kill "$(cat "$STATE_DIR/auth-server.pid")" 2>/dev/null || true
  redis-cli -h 127.0.0.1 -p 6379 shutdown nosave >/dev/null 2>&1 || true
  pg_ctlcluster "$PG_VERSION" main stop || true
  exit 0
fi

log "logs: $STATE_DIR/auth-server.log"
exit 0
