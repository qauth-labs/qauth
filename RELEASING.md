# Releasing QAuth

Releases are a maintainer's job. CI builds, checks and stages everything; a
maintainer pushes the tag and approves what CI staged.

**One tag releases everything at QAuth's version.** A tag `vX.Y.Z` (a release)
or `vX.Y.Z-rc.N` (a release candidate) starts two workflows:

| Workflow             | What it releases at that version                                           | Environment |
| -------------------- | -------------------------------------------------------------------------- | ----------- |
| `release-images.yml` | The server images `auth-server` and `migration-runner`, signed             | `release`   |
| `release-npm.yml`    | Every SDK package in `libs/sdk/`, for example `@qauth-labs/resource-guard` | `npm`       |

There are no per-package versions or tags. QAuth's version lives in its tags
and in the `## [X.Y.Z]` sections of `CHANGELOG.md`; every `package.json` in the
repository stays at `0.0.0`, and the npm workflow writes the tag's version into
each SDK package just before it packs it. So the tag is the only place a
version is decided, and the SDK release notes are QAuth's CHANGELOG section.

Both workflows live in the repository's workflows directory. Neither uses a
stored token: images are pushed with the run's own token and signed through its
OIDC identity, and npm accepts the packages through trusted publishing.

## The version rule

- Images and SDK packages carry the same version: the tag's.
- A release `vX.Y.Z` tags the images `X.Y.Z` and `X.Y`, and puts the packages
  on npm's `latest` dist-tag.
- A release candidate `vX.Y.Z-rc.N` tags the images `X.Y.Z-rc.N` only, and puts
  the packages on `next`.
- There is no `latest` image tag before 1.0, and the npm workflow refuses a
  `1.x` version until the stability review of ADR-018 §5 has happened.
- Nothing before 1.0 is covered by the stability promise: a minor `0.Y` may
  break, and the CHANGELOG says how.

## One-time setup

1. **Environments.** In the repository settings (Settings → Environments):
   - `release`: add yourself as required reviewer, and limit deployment
     branches and tags to the tag pattern `v*`.
   - `npm`: the same, yourself as required reviewer and tags `v*`.
2. **Images.** After the first image release, open each package
   (`qauth/auth-server`, `qauth/migration-runner`) in the organization's
   packages, set its visibility to public, and link it to this repository if it
   is not linked already. New organization packages start private.
3. **npm, per SDK package.** npm sets up a trusted publisher in the package's
   own settings page, so the package has to exist first.
   1. A placeholder `0.0.0`, published once by hand with 2FA and deprecated.
      `@qauth-labs/resource-guard@0.0.0` is already published and deprecated.
      For a later SDK, from an empty directory:
      ```sh
      pkg='@qauth-labs/new-sdk'   # the new SDK's package name
      npm init --scope=@qauth-labs -y
      npm pkg set "name=$pkg" version=0.0.0 \
        description='Placeholder; see https://github.com/qauth-labs/qauth'
      echo "# $pkg" > README.md
      npm publish --access public
      npm deprecate "$pkg@0.0.0" 'Placeholder; install a real version.'
      ```
   2. In the package's settings on npmjs.com, add a trusted publisher with
      exactly these values:

      | Field                | Value                               |
      | -------------------- | ----------------------------------- |
      | Organization or user | `qauth-labs`                        |
      | Repository           | `qauth`                             |
      | Workflow filename    | `release-npm.yml`                   |
      | Environment name     | `npm`                               |
      | Allowed actions      | stage publishing only (the default) |

      The fields are case-sensitive, and npm checks them only at publish time.

   3. Push the first release tag **within 2 days**: npm lets a new
      trusted-publisher configuration expire if its first publish does not come
      in that time. If it expires, delete it and add it again.

## Release

1. On a branch, move the `## [Unreleased]` notes in `CHANGELOG.md` under
   `## [X.Y.Z] - <date>` and merge it through a pull request. A release
   candidate has no section of its own: its notes are the `Unreleased` section
   at the tagged commit.
2. Tag the merge commit and push the tag:
   ```sh
   git tag -s vX.Y.Z <merge commit>
   git push origin vX.Y.Z
   ```
3. Two runs start. Approve both environments:
   - `release-images`: each image is built, pushed by digest, signed and
     attested. The run summary lists the digests.
   - `release-npm`: every SDK is packed at `X.Y.Z`, checked, installed into an
     empty project, and staged on npm with provenance. The run then leaves a
     draft release holding the SDK tarballs, with the CHANGELOG section as its
     notes.
4. Approve each staged package on npmjs.com (the package's Staged Packages tab,
   or `npm stage approve <id>` with 2FA). Only now is it installable.
5. Verify, then publish the draft release:
   - one image digest, as the
     [Published images](https://docs.qauth.dev/operate/images/) page shows;
   - each package from a clean directory:
     ```sh
     npm view @qauth-labs/resource-guard@X.Y.Z dist.attestations
     npm install @qauth-labs/resource-guard@X.Y.Z && npm audit signatures
     ```

Every pull request runs the npm workflow as a dry run: it stamps the newest
version `CHANGELOG.md` names into each SDK, packs, checks and installs it, and
publishes nothing.

## Rollback

Never unpublish: a version once seen must stay resolvable for whoever pinned it.

- **A bad package version:** deprecate it, then release a fixed QAuth version.
  For example, `npm deprecate '@qauth-labs/resource-guard@0.2.0' 'Broken; use 0.2.1.'`.
- **A bad `latest` or `next`:** point the dist-tag back at the previous good
  version, for example
  `npm dist-tag add '@qauth-labs/resource-guard@0.1.9' latest`.
- **A staged package you do not want:** reject it on npmjs.com instead of
  approving it, and delete the draft release.
- **A bad image:** deployments pin digests, so announce the previous good
  digest; a published tag is never moved to different content.
