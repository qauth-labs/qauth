# Releasing QAuth

Releases are a maintainer's job. CI builds, checks and stages everything; a
maintainer pushes the tag and approves what CI staged. Two kinds of release
exist, and each is started by its own tag:

| Tag                               | What it releases                                            | Workflow             |
| --------------------------------- | ----------------------------------------------------------- | -------------------- |
| `vX.Y.Z`, `vX.Y.Z-rc.N`           | The server: the `auth-server` and `migration-runner` images | `release-images.yml` |
| `<sdk>@X.Y.Z`, `<sdk>@X.Y.Z-rc.N` | One SDK package on npm, for example `resource-guard@0.1.0`  | `release-npm.yml`    |

Both workflows live in the repository's workflows directory. Neither uses a
stored token: images are pushed with the run's own token and signed through its
OIDC identity, and npm accepts the package through trusted publishing.

## One-time setup

Do these once, before the first release of each kind.

1. **Environments.** In the repository settings (Settings → Environments),
   create:
   - `release`: required reviewer yourself; deployment branches and tags limited
     to the tag pattern `v*`.
   - `npm`: required reviewer yourself; deployment tags limited to `*@*`.
2. **Images.** Nothing to do before the first push. After it, open each package
   (`qauth/auth-server`, `qauth/migration-runner`) in the organization's
   packages, set its visibility to public, and link it to this repository if it
   is not linked already. New organization packages start private.
3. **npm, per SDK package.** npm sets up a trusted publisher in the package's
   own settings page, so the package has to exist first:
   1. Publish a placeholder once from your machine, with 2FA: a `0.0.0` that
      holds only a README pointing at this repository. For example, for
      `@qauth-labs/resource-guard`, from an empty directory:
      ```sh
      npm init --scope=@qauth-labs -y
      npm pkg set name=@qauth-labs/resource-guard version=0.0.0 \
        description='Placeholder; see https://github.com/qauth-labs/qauth'
      echo '# @qauth-labs/resource-guard' > README.md
      npm publish --access public
      npm deprecate @qauth-labs/resource-guard@0.0.0 'Placeholder; install a real version.'
      ```
   2. In the package's settings on npmjs.com, add a trusted publisher:
      organization `qauth-labs`, repository `qauth`, workflow filename
      `release-npm.yml`, environment `npm`. Leave "Allowed actions" at stage
      publishing only, so every version waits for your 2FA approval.
   3. Release the first real version **within 2 days**. npm lets a new
      trusted-publisher configuration expire if its first publish does not come
      in that time; then delete it and create it again.

## Server images

1. On a branch, move the `## [Unreleased]` notes in `CHANGELOG.md` under
   `## [X.Y.Z] - <date>` (release candidates have no section), and merge it
   through a pull request.
2. Tag the merge commit and push the tag:
   ```sh
   git tag -s vX.Y.Z <merge commit>
   git push origin vX.Y.Z
   ```
3. Approve the `release` environment in the workflow run. Each image is built,
   pushed by digest, signed and attested; the run summary lists the digests.
4. Verify one digest as the [Published images](https://docs.qauth.dev/operate/images/)
   page shows, then announce the digests, not the tags.

Tags: `X.Y.Z`, plus `X.Y` for a release. A release candidate gets only its own
version. There is no `latest` before 1.0.

## SDK packages

### The version rule

- Each SDK has its own version, independent of the server and of the other SDKs.
- Before 1.0 an SDK stays on `0.x`; the release tooling refuses `1.0.0` until
  the stability review of ADR-018 §5 has happened.
- A release candidate is `0.Y.Z-rc.N` and goes to the `next` dist-tag. A release
  is `0.Y.Z` and goes to `latest`.
- Nothing before 1.0 is covered by the stability promise: a minor `0.Y` may
  break, and its changelog says how.

### Release

1. On a branch from `main`, set the version and write the changelog section:
   ```sh
   pnpm nx release version 0.1.0-rc.0 --projects resource-guard
   pnpm nx release changelog 0.1.0-rc.0 --projects resource-guard
   ```
   These update the SDK's `package.json`, the lockfile and its `CHANGELOG.md`.
   Nx neither commits nor tags. Commit, open a pull request and merge it. The
   `release-npm` dry run on that pull request packs, checks and installs the
   package exactly as the release will.
2. Tag the merge commit and push the tag:
   ```sh
   git tag -s resource-guard@0.1.0-rc.0 <merge commit>
   git push origin resource-guard@0.1.0-rc.0
   ```
3. The `release-npm` run checks the tag against the package's version and
   changelog, packs and checks the package again, and waits for the `npm`
   environment. Approve it: the package is staged on npm with provenance.
4. Approve the staged version on npmjs.com (the package's Staged Packages tab,
   or `npm stage approve <id>` with 2FA). Only now is it installable.
5. Check it from a clean directory, then publish the draft release the run
   created with the same tarball:
   ```sh
   npm view @qauth-labs/resource-guard@0.1.0-rc.0 dist.attestations
   npm install @qauth-labs/resource-guard@next && npm audit signatures
   ```

### Rollback

Never unpublish: a version once seen must stay resolvable for whoever pinned it.

- **A bad version:** `npm deprecate @qauth-labs/<sdk>@<version> '<why, and what to use>'`.
  Then release a fixed version.
- **A bad `latest` or `next`:** point the dist-tag back at the previous good
  version: `npm dist-tag add @qauth-labs/<sdk>@<good version> latest`.
- **A staged version you do not want:** reject it on npmjs.com instead of
  approving it, and delete the draft release.
