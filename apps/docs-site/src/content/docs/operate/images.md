---
title: Published images
description: The container images each QAuth release publishes, how to run them by digest, how to verify their signature, provenance and SBOM before you do, and how to build your own image with an AuthMethod plugin added.
sidebar:
  order: 9
lastVerified: '2026-11-05'
---

Each QAuth release publishes two container images, built once from the
release tag by the repository's `release-images` workflow
(`release-images.yml` in the workflows directory):

| Image                                       | What it is                                                                    |
| ------------------------------------------- | ----------------------------------------------------------------------------- |
| `ghcr.io/qauth-labs/qauth/auth-server`      | The authorization server, from `apps/auth-server/Dockerfile`                  |
| `ghcr.io/qauth-labs/qauth/migration-runner` | The program every upgrade runs first, from `apps/migration-runner/Dockerfile` |

Both are `linux/amd64` only for now.

The developer portal is not published as an image. Its Dockerfile writes the
auth server's public URL (`VITE_AUTH_SERVER_URL`) into the browser bundle at
build time, so one image could only ever talk to one host. Build it from
source with your own URL, as the [Docker guide](/operate/docker/) shows.

## Tags and digests

A release `vX.Y.Z` is tagged `X.Y.Z` and `X.Y`. A release candidate
`vX.Y.Z-rc.N` is tagged only `X.Y.Z-rc.N`, so it never moves a stable tag.
There is no `latest` tag before 1.0.

Tags can move; a digest cannot. Pin the digest that the release's workflow run
lists in its summary, and keep the tag only as a readable comment:

```yaml
services:
  migration-runner:
    image: ghcr.io/qauth-labs/qauth/migration-runner@sha256:<digest> # 0.2.0
  auth-server:
    image: ghcr.io/qauth-labs/qauth/auth-server@sha256:<digest> # 0.2.0
```

In the repository's `docker-compose.yml`, these two lines replace the `build:`
blocks of the same services. Everything else stays the same: the environment,
the keys and the order (the migration runner first, then the server). See
[Upgrades](/operate/upgrades/) for that order on every later version.

## Verify before you run

Every image digest is signed with cosign, keyless, by the release workflow's
own identity. Two attestations are attached to the same digest: build
provenance (SLSA) and an SPDX SBOM. Check all three before you deploy a digest.

The signature, with [cosign](https://docs.sigstore.dev/cosign/) 3.0 or later. The release
workflow signs with cosign 3, which stores the signature in the newer Sigstore bundle format;
cosign 2.x does not look there and reports `no signatures found` for a signed image:

```bash
cosign verify ghcr.io/qauth-labs/qauth/auth-server@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/qauth-labs/qauth/.github/workflows/release-images.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The provenance and the SBOM, with the `gh` command-line tool. These need no cosign, and they
check the same signing identity (the release workflow at a tag), so they also serve as the
alternative when cosign 3 is not at hand:

```bash
gh attestation verify oci://ghcr.io/qauth-labs/qauth/auth-server@sha256:<digest> \
  --repo qauth-labs/qauth

gh attestation verify oci://ghcr.io/qauth-labs/qauth/auth-server@sha256:<digest> \
  --repo qauth-labs/qauth --predicate-type https://spdx.dev/Document/v2.3
```

The first command proves which workflow run, commit and tag built the image.
The second shows the packages inside it. Run the same commands for the
`migration-runner` digest.

## Add a plugin to the image

An [AuthMethod plugin](/extend/auth-method-contract/) is an npm package that the server imports by
name at boot, from its own `node_modules`. The server never fetches code, so a deployment that uses
a plugin runs its own image: the published one, with the package added on top.

The published `auth-server` image runs QAuth's sources from `/app`, a `pnpm deploy` tree, and
imports a listed plugin from `/app/node_modules/<package name>`. Install the plugin in a build
stage with npm and copy its directory there:

- **nested** (`--install-strategy=nested`), so the plugin's own dependencies, such as the plugin
  SDK, sit inside its directory and travel with it;
- **without its peer dependencies** (`--omit=peer`), so it takes `zod` from the server: a plugin's
  config schema must be built with the server's Zod, or the boot cannot read its secret members;
- **without install scripts** (`--ignore-scripts`), and at an exact version.

```dockerfile
# syntax=docker/dockerfile:1.7
# The QAuth release, by the digest you verified above.
ARG QAUTH_IMAGE=ghcr.io/qauth-labs/qauth/auth-server@sha256:<digest>

# The build stage writes the files the server will run: pin it by digest too.
FROM node:26-alpine@sha256:<digest> AS plugin
WORKDIR /plugin
RUN npm init --yes > /dev/null \
 && npm install --omit=dev --omit=peer --install-strategy=nested --ignore-scripts \
      @example/qauth-plugin-corp-sso@1.2.3

FROM ${QAUTH_IMAGE}
COPY --from=plugin --chown=nodejs:nodejs \
  /plugin/node_modules/@example/qauth-plugin-corp-sso \
  /app/node_modules/@example/qauth-plugin-corp-sso
```

Copy one directory per plugin, at the same path below `/app/node_modules` as its package name.
Then list the package and, unless it is on QAuth's first-party list, turn on the plugin API:

```bash
AUTH_METHOD_PLUGINS=@example/qauth-plugin-corp-sso
PLUGIN_API_ENABLED=true
```

At boot the server logs `AuthMethod plugin @example/qauth-plugin-corp-sso loaded` with the
plugin's `id` and `type`. A package it cannot import stops the boot, and with
`PLUGIN_API_ENABLED` off it logs a warning that names the package and says why it was skipped. A
realm admin then enables and configures the plugin through the admin API
([Installing and enabling a plugin](/extend/auth-method-contract/#installing-and-enabling-a-plugin)).

A plugin release is built for one QAuth contract version, so rebuild this image at every QAuth
upgrade with the plugin version made for the new release; a mismatch stops the boot and says so.
Your image is no longer the digest QAuth signed: verify the base digest before you build on it,
and pin the build stage by digest as well. `npm audit signatures` in the build stage checks that
the registry's signatures and attestations are valid, not who built the package: to know that,
read the version's provenance (on npmjs.com, or the attestation at
`npm view <package>@<version> dist.attestations.url`) and check that it names the plugin's own
repository and release workflow. Plugin code runs
in the server's process, beside its keys in a single deployment, so add only a package you trust
as you trust the server.

For example, QAuth's own GitHub plugin, `@qauth-labs/plugin-github`, installs this way: the
end-to-end suite of its repository builds its test image with this recipe on the released server
image, and its README names the plugin version made for each QAuth release.
The example's sources are in [qauth-labs/plugin-github](https://github.com/qauth-labs/plugin-github).

## What a release runs

1. A maintainer pushes the tag. A stable tag needs its `## [X.Y.Z]` section in
   `CHANGELOG.md` first, or the workflow stops.
2. The publish jobs wait in the `release` environment until a maintainer
   approves them.
3. Each image is built once, pushed by digest, signed and attested, and its
   digest is written to the run's summary.

A manual run of the workflow, and a pull request that changes it, build both
images and push nothing.

The same tag also stages QAuth's SDK packages on npm at the same version, in a
second workflow behind its own approval. The images and the packages of a
release always carry the same version.
