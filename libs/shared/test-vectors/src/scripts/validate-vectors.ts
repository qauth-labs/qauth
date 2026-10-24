/**
 * Validate every file under `test-vectors/` (the `test-vectors:validate`
 * target). Prints each problem and exits 1 when there is one, or when there
 * are no vector files at all. Nothing imports this script.
 */
import { validateVectorTree } from '../lib/validate';

const reports = validateVectorTree();
let problems = 0;
for (const { file, problems: found } of reports) {
  for (const problem of found) {
    console.error(`${file}: ${problem.path || '(file)'}: ${problem.message}`);
  }
  problems += found.length;
}

if (reports.length === 0) {
  console.error('test-vectors: no vector files found');
  process.exitCode = 1;
} else if (problems > 0) {
  console.error(`test-vectors: ${problems} problem(s) in ${reports.length} file(s)`);
  process.exitCode = 1;
} else {
  console.log(`test-vectors: ${reports.length} file(s) valid`);
}
