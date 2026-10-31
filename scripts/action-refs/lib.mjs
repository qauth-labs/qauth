/**
 * Pinned action references (#796): every `uses:` in a workflow names a major
 * tag or a full commit SHA. `check.mjs` is the CLI that reads the workflow
 * directory and reports; this module holds the rules, so the tests drive them
 * on strings.
 *
 * A major tag (`actions/checkout@v7`) follows its publisher's fixes within one
 * major; a full commit SHA does not move at all. A branch moves with every
 * push, and `latest` or no ref at all is whatever was published last, so
 * neither says which code runs. A minor or patch tag (`@v7.0.1`) is refused
 * too: its publisher can move it like any tag, so it pins nothing a major tag
 * does not. A workflow that needs one exact version pins the commit SHA and
 * names the version in a comment, as the release workflows do.
 *
 * A Docker image (`docker://image:tag`) has no major tags of its own, so it
 * must name a tag that is a version number and nothing else (`:1.2.3`, not a
 * rolling `:1-nightly`), or a sha256 digest. A local action or workflow
 * (`./path`) comes from the same commit as the workflow that calls it and
 * names no ref.
 *
 * The workflow is read line by line, not parsed as YAML: a line whose key is
 * `uses` must carry one reference, plain or quoted, with at most a comment
 * after it. A `uses:` line that cannot be read that way is refused rather than
 * skipped, and so is any other line with a `uses` key on it (a flow mapping
 * `- { uses: … }`, a quoted key `"uses":`), so an unusual spelling cannot hide
 * a reference. This fails closed: an action input named `uses` under `with:`,
 * or a `uses:` line inside a `run:` script, is refused too.
 *
 * Zero runtime dependencies — no imports at all.
 */

const MAJOR_TAG = /^v\d+$/;
const COMMIT_SHA = /^[0-9a-f]{40}$/;
const VERSION_TAG = /^v\d+(\.\d+)+$/;
const HEX = /^[0-9a-f]{7,40}$/i;
const DOCKER_PREFIX = 'docker://';
const DOCKER_DIGEST = /@sha256:[0-9a-f]{64}$/;
const DOCKER_VERSION = /^v?\d+(\.\d+)*$/;

/** A `uses` key, alone or as the first key of a list item; group 1 is the rest of the line. */
const USES_KEY = /^\s*(?:-\s+)?uses\s*:(\s.*)?$/;
/** A `uses` key anywhere else on a line: in a flow mapping, quoted, or after an anchor or tag. */
const USES_ELSEWHERE = /(?:^|[\s{,?])["']?uses["']?\s*:(?:\s|$)/;

const PIN = 'pin a major tag (@v1) or a full commit SHA';
const PIN_IMAGE = 'pin a version tag (:1.2.3) or a sha256 digest';
const UNREADABLE = 'cannot be read as one plain or quoted reference on this line';

/**
 * What is wrong with one `uses:` reference, or `null` when it is pinned.
 *
 * @param {string} reference the value of a `uses:` key
 * @returns {string | null} the problem, worded to follow the reference
 */
export function referenceProblem(reference) {
  if (reference.startsWith('./')) return null;
  if (reference.startsWith(DOCKER_PREFIX)) {
    return imageProblem(reference.slice(DOCKER_PREFIX.length));
  }

  const at = reference.lastIndexOf('@');
  const ref = at === -1 ? '' : reference.slice(at + 1);
  if (MAJOR_TAG.test(ref) || COMMIT_SHA.test(ref)) return null;
  if (ref === '') return `names no ref; ${PIN}`;
  if (ref === 'latest') return `names "latest", which moves with every release; ${PIN}`;
  if (VERSION_TAG.test(ref)) {
    return `names the version tag ${ref}; pin its major tag (@${ref.split('.')[0]}) or its full commit SHA`;
  }
  if (HEX.test(ref)) {
    return 'names an abbreviated or upper-case commit SHA; pin the full 40-character lower-case SHA';
  }
  return `names "${ref}", which is neither a major tag nor a full commit SHA (a branch moves with every push); ${PIN}`;
}

/** What is wrong with a `docker://` image, or `null` when it is pinned. */
function imageProblem(image) {
  if (DOCKER_DIGEST.test(image)) return null;
  // The tag follows the last colon of the last path segment; a colon before
  // that belongs to a registry's port.
  const name = image.slice(image.lastIndexOf('/') + 1);
  const colon = name.lastIndexOf(':');
  const tag = colon === -1 ? '' : name.slice(colon + 1);
  if (DOCKER_VERSION.test(tag)) return null;
  if (tag === '') return `names no image tag, which means "latest"; ${PIN_IMAGE}`;
  return `names the image tag "${tag}", which is not a version; ${PIN_IMAGE}`;
}

/**
 * The single reference a `uses:` line carries, or `null` when the rest of the
 * line is not one plain or quoted value with at most a comment after it.
 */
function readReference(rest) {
  const text = rest.trim();
  if (text === '' || text.startsWith('#')) return null;

  let value;
  let after;
  if (text.startsWith("'") || text.startsWith('"')) {
    const end = text.indexOf(text[0], 1);
    if (end === -1) return null;
    value = text.slice(1, end);
    after = text.slice(end + 1);
  } else {
    // In a plain YAML value a comment starts at a `#` after whitespace.
    const comment = text.search(/\s#/);
    value = comment === -1 ? text : text.slice(0, comment);
    after = comment === -1 ? '' : text.slice(comment);
  }
  after = after.trim();
  if (after !== '' && !after.startsWith('#')) return null;
  value = value.trim();
  return value === '' ? null : value;
}

/**
 * Every `uses:` line of one workflow, with what is wrong with it.
 *
 * @param {string} text the workflow file's contents
 * @returns {{ line: number, uses: string, problem: string | null }[]} in file
 *   order; `line` counts from 1, and `uses` is the reference, or the whole
 *   trimmed line when it cannot be read
 */
export function workflowReferences(text) {
  const references = [];
  for (const [index, content] of text.split(/\r?\n/).entries()) {
    const match = USES_KEY.exec(content);
    if (match === null) {
      // Only the text before a comment: `name: Build # uses: x@main` has no key.
      if (USES_ELSEWHERE.test(content.split(/(?:^|\s)#/, 1)[0])) {
        references.push({ line: index + 1, uses: content.trim(), problem: UNREADABLE });
      }
      continue;
    }
    const reference = readReference(match[1] ?? '');
    if (reference === null) {
      references.push({ line: index + 1, uses: content.trim(), problem: UNREADABLE });
    } else {
      references.push({ line: index + 1, uses: reference, problem: referenceProblem(reference) });
    }
  }
  return references;
}
