/**
 * Write the admin permission catalog's stable surface (#507),
 * `apps/docs-site/public/schemas/admin-permissions.json`, from the registry.
 * Run through `pnpm exec nx run auth-server:admin-permissions-export`; the
 * stable-surface check runs it too, fails when the committed file differs, and
 * compares the file with the latest release. The file stays plain
 * `JSON.stringify` output, which `.oxfmtrc.json` leaves alone, like the event
 * schemas. This script is the only I/O of the surface, and nothing imports it.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { PERMISSION_REGISTRY } from './app/helpers/admin-permissions';
import {
  ADMIN_PERMISSIONS_SURFACE_PATH,
  adminPermissionsSurfaceText,
} from './app/helpers/admin-permissions-surface';

const repoRoot = resolve(__dirname, '..', '..', '..');
const target = join(repoRoot, ADMIN_PERMISSIONS_SURFACE_PATH);
mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, adminPermissionsSurfaceText(PERMISSION_REGISTRY));
console.log(`auth-server: wrote ${ADMIN_PERMISSIONS_SURFACE_PATH}`);
