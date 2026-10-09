# Offline security-review image for QAuth.
#
# Build it from the repository root:
#
#   docker build -f tools/security-review/Dockerfile -t qauth-review .
#
# What it is for: a reviewer, human or automated, gets the whole workspace
# built, with every dependency already installed, and can then work with NO
# network access at all. Everything a review needs later is fetched here,
# while the image builds.
#
# What is inside:
#   - the full checkout at /src, tests and git history included (see
#     Dockerfile.dockerignore next to this file);
#   - node_modules installed from the lockfile, and every project built;
#   - PostgreSQL 18 and Redis, so tools/security-review/start-stack.sh can run
#     the real auth-server on http://localhost:3000 inside the container.
#
# What is not inside: a Docker daemon. The `test-integration` suites use
# testcontainers and cannot run here; the unit suites and the local stack can.
#
# docs/security/threat-model.md tells a reviewer what to look at and how
# findings are rated. SECURITY.md says how to report one.

FROM node:24-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CI=true \
    NX_DAEMON=false \
    NX_NO_CLOUD=true

# PostgreSQL 18 comes from the PostgreSQL project's own apt repository (Debian
# bookworm ships 15). Redis 7 comes from Debian.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl git build-essential python3 postgresql-common redis-server \
    && /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y \
    && apt-get install -y --no-install-recommends postgresql-18 \
    && rm -rf /var/lib/apt/lists/*

# The pnpm version CI uses.
RUN npm install -g pnpm@11.4.0

COPY . /src
WORKDIR /src

RUN pnpm install --frozen-lockfile

# Build every project the way CI does. A failing build fails the image.
RUN pnpm exec nx run-many -t build

# Run the unit tests once so a reviewer knows the image works. A failing test
# is reported but does not fail the build: the image is still useful for
# finding out why.
RUN pnpm exec nx run-many -t test \
    || echo "WARNING: some unit tests failed while building the review image"

RUN chmod +x tools/security-review/start-stack.sh

CMD ["bash"]
