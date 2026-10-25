---
title: Published images
description: The container images each QAuth release publishes, how to run them by digest, and how to verify their signature, provenance and SBOM before you do.
sidebar:
  order: 9
lastVerified: '2026-10-25'
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

The signature, with [cosign](https://docs.sigstore.dev/cosign/) 2.0 or later:

```bash
cosign verify ghcr.io/qauth-labs/qauth/auth-server@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/qauth-labs/qauth/.github/workflows/release-images.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The provenance and the SBOM, with the `gh` command-line tool:

```bash
gh attestation verify oci://ghcr.io/qauth-labs/qauth/auth-server@sha256:<digest> \
  --repo qauth-labs/qauth

gh attestation verify oci://ghcr.io/qauth-labs/qauth/auth-server@sha256:<digest> \
  --repo qauth-labs/qauth --predicate-type https://spdx.dev/Document/v2.3
```

The first command proves which workflow run, commit and tag built the image.
The second shows the packages inside it. Run the same commands for the
`migration-runner` digest.

## What a release runs

1. A maintainer pushes the tag. A stable tag needs its `## [X.Y.Z]` section in
   `CHANGELOG.md` first, or the workflow stops.
2. The publish jobs wait in the `release` environment until a maintainer
   approves them.
3. Each image is built once, pushed by digest, signed and attested, and its
   digest is written to the run's summary.

A manual run of the workflow, and a pull request that changes it, build both
images and push nothing.
