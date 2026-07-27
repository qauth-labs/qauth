/**
 * Key-storage assurance — HAIP §9.2 / §4.5.1 key attestations (issue #308).
 *
 * Four modules, one gate:
 *
 * - `attack-potential` — the OID4VCI Appendix D §D.2 vocabulary and its order.
 * - `attesting-issuers` — the TRANSITIVE path: which issuance chains the
 *   operator recorded as validating key attestations at issuance. Start here;
 *   it carries the reasoning that shapes everything else.
 * - `key-attestation` — validation of an Appendix D attestation an ecosystem
 *   conveyed into the presentation, including the `cnf` binding without which
 *   the rest is theatre.
 * - `key-storage-assurance` — the resolver the presentation seam calls, and the
 *   evidence #237 consumes.
 *
 * Nothing here authenticates anyone. This gate is layered AFTER holder binding
 * (#234) and runs alongside issuer trust (#236); it never substitutes for either
 * and never relaxes either.
 */

export * from './attack-potential';
export * from './attesting-issuers';
export * from './key-attestation';
export * from './key-storage-assurance';
export * from './key-storage-assurance-rejection';
