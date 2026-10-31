#!/usr/bin/env bash
#
# The upgrade test (#475, ADR-018 §5): start a released QAuth, write data
# through its HTTP API, upgrade to this checkout with the migration runner
# ONLY, and check that nothing was lost. Then run the released server again on
# the migrated database (the rolling-upgrade leg), the proof of "expand, then
# contract": old code must still work after the new migrations ran.
#
# Each command is one step of the `upgrade-test` CI job (the `Upgrade test`
# workflow); `all` runs them in order for a local run. Every docker command is
# printed before it runs. Secrets reach the containers by variable NAME
# (`-e KEK`), so no printed command carries one.
#
# Usage:
#   UPGRADE_BASELINE=v0.1.3 scripts/upgrade-test/upgrade-test.sh all
#   UPGRADE_BASELINE=v0.1.3 scripts/upgrade-test/upgrade-test.sh <command>
#
# Commands, in the order the job runs them:
#   baseline-images  build the baseline's auth-server and migration-runner
#                    images from its tag (git archive of the tag, its own
#                    Dockerfiles)
#   head-images      build both images from this checkout
#   services         start Postgres 18, Redis 7 and Mailpit (the SMTP sink the
#                    servers send their verification mail to) on a private
#                    network
#   secrets          generate the signing key pair, KEK and cookie secret both
#                    servers share (the same keys, or old tokens fail for the
#                    wrong reason)
#   baseline-migrate run the baseline's migration runner on the empty database
#   start baseline   start the baseline server and wait for /health
#   populate         write the scenario through the baseline; save the state file
#   stop baseline    stop the baseline server
#   migrate          THE upgrade: run this checkout's migration runner. Nothing
#                    else runs between the two servers.
#   start head       start this checkout's server and wait for /health
#   verify           check the baseline's data on the new server
#   smoke            the version-agnostic smoke tests on the running server
#   wire-suite       seed the wire-suite client and run apps/wire-suite
#   stop head        stop the new server
#   start rolling    start the BASELINE server on the migrated database
#   smoke            again, now against the baseline server
#   logs             print every container's state and logs
#   down             remove the containers and the network
#
# Environment (defaults in brackets):
#   UPGRADE_BASELINE        the release tag to upgrade from (required for the
#                           baseline commands)
#   UPGRADE_WORK_DIR        state file, secrets, baseline sources [tmp/upgrade-test]
#   UPGRADE_PREFIX          container and network name prefix [qauth-upgrade]
#   UPGRADE_HTTP_PORT       the server's port on localhost [3000]
#   UPGRADE_PG_PORT         Postgres's port on localhost [5432]
#   UPGRADE_MAIL_PORT       Mailpit's HTTP API port on localhost [8025]
#   UPGRADE_*_IMAGE         override an image name (BASELINE_SERVER, BASELINE_RUNNER,
#                           HEAD_SERVER, HEAD_RUNNER)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="${UPGRADE_WORK_DIR:-$REPO_ROOT/tmp/upgrade-test}"
PREFIX="${UPGRADE_PREFIX:-qauth-upgrade}"
HTTP_PORT="${UPGRADE_HTTP_PORT:-3000}"
PG_PORT="${UPGRADE_PG_PORT:-5432}"
MAIL_PORT="${UPGRADE_MAIL_PORT:-8025}"
BASELINE="${UPGRADE_BASELINE:-}"

BASELINE_SERVER_IMAGE="${UPGRADE_BASELINE_SERVER_IMAGE:-qauth-upgrade/auth-server:${BASELINE:-unset}}"
BASELINE_RUNNER_IMAGE="${UPGRADE_BASELINE_RUNNER_IMAGE:-qauth-upgrade/migration-runner:${BASELINE:-unset}}"
HEAD_SERVER_IMAGE="${UPGRADE_HEAD_SERVER_IMAGE:-qauth-upgrade/auth-server:head}"
HEAD_RUNNER_IMAGE="${UPGRADE_HEAD_RUNNER_IMAGE:-qauth-upgrade/migration-runner:head}"

NETWORK="$PREFIX"
POSTGRES="$PREFIX-postgres"
REDIS="$PREFIX-redis"
MAIL="$PREFIX-mail"
# Pinned: the mail API the test reads is Mailpit's.
MAILPIT_IMAGE=axllent/mailpit:v1.27.11
DB_PASSWORD=qauth_upgrade_password
# Inside the network, and from this host for the test and the seed command.
NETWORK_DATABASE_URL="postgresql://qauth:$DB_PASSWORD@postgres:5432/qauth"
HOST_DATABASE_URL="postgresql://qauth:$DB_PASSWORD@localhost:$PG_PORT/qauth"
# The issuer both servers are configured with, and the URL the test uses.
BASE_URL="http://localhost:$HTTP_PORT"
MAIL_URL="http://localhost:$MAIL_PORT"
SECRETS_DIR="$WORK_DIR/secrets"
STATE_FILE="$WORK_DIR/state.json"

say() { printf '%s\n' "$*" >&2; }
fail() {
  # An error annotation in CI, a plain line elsewhere.
  if [ -n "${CI:-}" ]; then
    printf '::error::%s\n' "$*" >&2
  else
    printf 'upgrade-test: %s\n' "$*" >&2
  fi
  exit 1
}
# Print a command, then run it.
run() {
  printf '+ %s\n' "$*" >&2
  "$@"
}

require_baseline() {
  [ -n "$BASELINE" ] || fail "UPGRADE_BASELINE is not set: name the release tag to upgrade from."
}

baseline_images() {
  require_baseline
  local source="$WORK_DIR/baseline-src"
  git -C "$REPO_ROOT" rev-parse --verify --quiet "refs/tags/$BASELINE" >/dev/null \
    || fail "$BASELINE is not a tag of this checkout (fetch the tags)."
  rm -rf "$source"
  mkdir -p "$source"
  # The tag's own tree, Dockerfiles included: the baseline is built exactly as
  # it was released, from a registry-independent source.
  run git -C "$REPO_ROOT" archive --output="$WORK_DIR/baseline-src.tar" "refs/tags/$BASELINE"
  run tar -x -f "$WORK_DIR/baseline-src.tar" -C "$source"
  rm -f "$WORK_DIR/baseline-src.tar"
  DOCKER_BUILDKIT=1 run docker build -f "$source/apps/auth-server/Dockerfile" -t "$BASELINE_SERVER_IMAGE" "$source"
  DOCKER_BUILDKIT=1 run docker build -f "$source/apps/migration-runner/Dockerfile" -t "$BASELINE_RUNNER_IMAGE" "$source"
}

head_images() {
  DOCKER_BUILDKIT=1 run docker build -f "$REPO_ROOT/apps/auth-server/Dockerfile" -t "$HEAD_SERVER_IMAGE" "$REPO_ROOT"
  DOCKER_BUILDKIT=1 run docker build -f "$REPO_ROOT/apps/migration-runner/Dockerfile" -t "$HEAD_RUNNER_IMAGE" "$REPO_ROOT"
}

services() {
  docker network inspect "$NETWORK" >/dev/null 2>&1 || run docker network create "$NETWORK" >/dev/null
  run docker run -d --name "$POSTGRES" --network "$NETWORK" --network-alias postgres \
    -p "127.0.0.1:$PG_PORT:5432" \
    -e POSTGRES_DB=qauth -e POSTGRES_USER=qauth -e POSTGRES_PASSWORD="$DB_PASSWORD" \
    postgres:18-alpine >/dev/null
  run docker run -d --name "$REDIS" --network "$NETWORK" --network-alias redis redis:7-alpine >/dev/null
  # Any SMTP credentials over plain SMTP: the servers need a user and password
  # set, and nothing leaves the network.
  run docker run -d --name "$MAIL" --network "$NETWORK" --network-alias mail \
    -p "127.0.0.1:$MAIL_PORT:8025" \
    -e MP_SMTP_AUTH_ACCEPT_ANY=1 -e MP_SMTP_AUTH_ALLOW_INSECURE=1 \
    "$MAILPIT_IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    if docker exec "$POSTGRES" pg_isready -U qauth -d qauth >/dev/null 2>&1 \
      && docker exec "$REDIS" redis-cli ping >/dev/null 2>&1 \
      && curl -fsS --max-time 2 "$MAIL_URL/api/v1/info" >/dev/null 2>&1; then
      # pg_isready answers during the image's init restart too; a query does not.
      if docker exec "$POSTGRES" psql -U qauth -d qauth -c 'SELECT 1' >/dev/null 2>&1; then
        say "Postgres, Redis and Mailpit are ready."
        return 0
      fi
    fi
    sleep 1
  done
  fail "Postgres, Redis or Mailpit did not become ready."
}

secrets() {
  mkdir -p "$SECRETS_DIR"
  chmod 700 "$SECRETS_DIR"
  if [ ! -f "$SECRETS_DIR/jwt-private.pem" ]; then
    (
      umask 077
      openssl genpkey -algorithm ed25519 -out "$SECRETS_DIR/jwt-private.pem"
      openssl pkey -in "$SECRETS_DIR/jwt-private.pem" -pubout -out "$SECRETS_DIR/jwt-public.pem"
      openssl rand -base64 32 >"$SECRETS_DIR/kek"
      openssl rand -base64 48 >"$SECRETS_DIR/session-cookie-secret"
    )
  fi
  say "One Ed25519 signing key pair, KEK and cookie secret in $SECRETS_DIR, shared by every server of the run."
}

load_secrets() {
  [ -f "$SECRETS_DIR/jwt-private.pem" ] || fail "No secrets in $SECRETS_DIR: run the secrets command first."
  JWT_PRIVATE_KEY="$(cat "$SECRETS_DIR/jwt-private.pem")"
  JWT_PUBLIC_KEY="$(cat "$SECRETS_DIR/jwt-public.pem")"
  KEK="$(cat "$SECRETS_DIR/kek")"
  SESSION_COOKIE_SECRET="$(cat "$SECRETS_DIR/session-cookie-secret")"
  export JWT_PRIVATE_KEY JWT_PUBLIC_KEY KEK SESSION_COOKIE_SECRET
}

# The runners print everything they do to the step's log, so their containers
# are removed as they exit.
baseline_migrate() {
  require_baseline
  run docker run --rm --name "$PREFIX-runner-baseline" --network "$NETWORK" \
    -e DATABASE_URL="$NETWORK_DATABASE_URL" "$BASELINE_RUNNER_IMAGE"
}

# The upgrade itself, and the only command between the baseline server and the
# new one.
migrate() {
  run docker run --rm --name "$PREFIX-runner-head" --network "$NETWORK" \
    -e DATABASE_URL="$NETWORK_DATABASE_URL" "$HEAD_RUNNER_IMAGE"
}

server_image() {
  case "$1" in
    baseline | rolling) printf '%s' "$BASELINE_SERVER_IMAGE" ;;
    head) printf '%s' "$HEAD_SERVER_IMAGE" ;;
    *) fail "Unknown server role '$1': baseline, head or rolling." ;;
  esac
}

start_server() {
  local role="$1" image container redis_db=0
  image="$(server_image "$role")"
  [ "$role" = head ] || require_baseline
  container="$PREFIX-server-$role"
  # The rolling leg runs after the wire suite, whose rate-limit file spends the
  # registration budget of this address on purpose. A Redis database of its
  # own keeps that budget from refusing the leg's registrations; the leg is
  # about the migrated schema, and Redis holds no schema.
  [ "$role" = rolling ] && redis_db=1
  load_secrets
  docker rm -f "$container" >/dev/null 2>&1 || true
  # The same configuration for every server of the run, as the wire-suite CI
  # job's, with raised rate limits (every request comes from one address; the
  # wire suite's code flows spend more than the default 30 token requests a
  # minute) and mail over SMTP to Mailpit: every release since 0.1.0 signs in
  # only verified accounts, and the mock provider delivers no verification mail.
  run docker run -d --name "$container" --network "$NETWORK" -p "127.0.0.1:$HTTP_PORT:3000" \
    -e NODE_ENV=production -e HOST=0.0.0.0 -e PORT=3000 -e LOG_LEVEL=info \
    -e DATABASE_URL="$NETWORK_DATABASE_URL" \
    -e REDIS_URL="redis://redis:6379/$redis_db" -e REDIS_HOST=redis -e REDIS_PORT=6379 -e REDIS_DB="$redis_db" \
    -e JWT_PRIVATE_KEY -e JWT_PUBLIC_KEY -e JWT_ISSUER="$BASE_URL" \
    -e KEK -e SESSION_COOKIE_SECRET -e SESSION_COOKIE_SECURE=false \
    -e EMAIL_PROVIDER=smtp -e SMTP_HOST=mail -e SMTP_PORT=1025 -e SMTP_SECURE=false \
    -e SMTP_USER=upgrade-test -e SMTP_PASSWORD=upgrade-test \
    -e EMAIL_FROM_ADDRESS=noreply@qauth.dev -e EMAIL_BASE_URL="$BASE_URL" \
    -e RATE_LIMIT_MAX=10000 -e REGISTRATION_RATE_LIMIT=100 -e LOGIN_RATE_LIMIT=100 \
    -e TOKEN_RATE_LIMIT=1000 -e AUTHORIZE_RATE_LIMIT=1000 -e INTROSPECT_RATE_LIMIT=1000 \
    -e USERINFO_RATE_LIMIT=1000 -e VERIFICATION_RATE_LIMIT=100 -e REGISTER_CLIENT_RATE_LIMIT=100 \
    "$image" >/dev/null
  local body=''
  for _ in $(seq 1 90); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$container")" != "true" ]; then
      fail "The $role server ($image) stopped before it became healthy (exit code $(docker inspect -f '{{.State.ExitCode}}' "$container")). Its log is in the logs step."
    fi
    body="$(curl -fsS --max-time 5 "$BASE_URL/health" 2>/dev/null || true)"
    case "$body" in
      *'"status":"ok"'*)
        say "The $role server ($image) is healthy at $BASE_URL."
        return 0
        ;;
    esac
    sleep 2
  done
  fail "The $role server ($image) did not report healthy. Last /health body: ${body:-<none>}"
}

stop_server() {
  local role="$1"
  server_image "$role" >/dev/null
  # Stopped, not removed: the logs step prints its log on a failure.
  run docker stop --time 10 "$PREFIX-server-$role" >/dev/null
}

upgrade_step() {
  local step="$1"
  mkdir -p "$WORK_DIR"
  (
    cd "$REPO_ROOT"
    QAUTH_UPGRADE_ALLOW_WRITES=1 \
      QAUTH_BASE_URL="$BASE_URL" \
      QAUTH_UPGRADE_DATABASE_URL="$HOST_DATABASE_URL" \
      QAUTH_UPGRADE_STATE="$STATE_FILE" \
      QAUTH_UPGRADE_MAIL_URL="$MAIL_URL" \
      run pnpm exec nx run "upgrade-test:$step" --skip-nx-cache --output-style=static
  )
}

# The wire suite against the upgraded database, seeded and run as the
# wire-suite CI job does: realm first, then the manifest's client through the
# operator seed command from this checkout, its secret handed over in the
# environment and masked in CI. The suite signs accounts in, and verifies each
# one through the mail the server delivered to Mailpit.
wire_suite() {
  local output secret
  run docker exec "$POSTGRES" psql -v ON_ERROR_STOP=1 -U qauth -d qauth \
    -c "INSERT INTO realms (name) VALUES ('master') ON CONFLICT (name) DO NOTHING" >/dev/null
  output="$(cd "$REPO_ROOT" && DATABASE_URL="$HOST_DATABASE_URL" pnpm --dir libs/infra/db exec tsx \
    src/scripts/seed-oauth-clients.ts --manifest="$REPO_ROOT/apps/wire-suite/seed/clients.json")"
  secret="$(printf '%s\n' "$output" \
    | awk '/^  wire-confidential$/ { found = 1; next } found && $1 == "secret:" { print $2; exit }')"
  if [ -z "$secret" ]; then
    printf '%s\n' "$output" | grep -v 'secret:' >&2 || true
    fail "The seed printed no secret for wire-confidential."
  fi
  # Masked in the CI log, should anything print it.
  [ -n "${CI:-}" ] && printf '::add-mask::%s\n' "$secret"
  printf '%s\n' "$output" | grep -E '^Seeded realm' >&2 || true
  (
    cd "$REPO_ROOT"
    QAUTH_WIRE_ALLOW_WRITES=1 \
      QAUTH_BASE_URL="$BASE_URL" \
      QAUTH_WIRE_CLIENT_ID=wire-confidential \
      QAUTH_WIRE_CLIENT_SECRET="$secret" \
      QAUTH_WIRE_MAIL_URL="$MAIL_URL" \
      run pnpm exec nx run wire-suite:run --skip-nx-cache --output-style=static
  )
}

logs() {
  local container
  say '--- containers ---'
  docker ps -a --filter "name=^$PREFIX-" --format '{{.Names}}\t{{.Image}}\t{{.Status}}' >&2 || true
  for container in $(docker ps -a --filter "name=^$PREFIX-" --format '{{.Names}}' | sort); do
    case "$container" in "$POSTGRES" | "$REDIS" | "$MAIL") continue ;; esac
    say ""
    say "--- $container: state ---"
    docker inspect -f '{{json .State}}' "$container" >&2 || true
    say "--- $container: log ---"
    docker logs "$container" >&2 2>&1 || true
  done
  say ""
  say "--- $POSTGRES: log ---"
  docker logs --tail 200 "$POSTGRES" >&2 2>&1 || true
}

down() {
  local containers=()
  mapfile -t containers < <(docker ps -aq --filter "name=^$PREFIX-")
  [ "${#containers[@]}" -eq 0 ] || docker rm -f "${containers[@]}" >/dev/null
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}

# On the way out of `all`: the logs when a step failed, then a clean slate.
finish() {
  local status=$?
  [ "$status" -eq 0 ] || logs
  down
  exit "$status"
}

all() {
  require_baseline
  trap finish EXIT
  down
  baseline_images
  head_images
  services
  secrets
  baseline_migrate
  start_server baseline
  upgrade_step populate
  stop_server baseline
  migrate
  start_server head
  upgrade_step verify
  upgrade_step smoke
  wire_suite
  stop_server head
  start_server rolling
  upgrade_step smoke
  say "upgrade-test: $BASELINE upgraded to this checkout, verified, and the rolling leg passed."
}

command="${1:-}"
[ $# -gt 0 ] && shift
case "$command" in
  baseline-images) baseline_images ;;
  head-images) head_images ;;
  services) services ;;
  secrets) secrets ;;
  baseline-migrate) baseline_migrate ;;
  migrate) migrate ;;
  start) start_server "${1:?start needs a role: baseline, head or rolling}" ;;
  stop) stop_server "${1:?stop needs a role: baseline, head or rolling}" ;;
  populate | verify | smoke) upgrade_step "$command" ;;
  wire-suite) wire_suite ;;
  logs) logs ;;
  down) down ;;
  all) all ;;
  *)
    sed -n '2,/^set -euo pipefail/p' "${BASH_SOURCE[0]}" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac
