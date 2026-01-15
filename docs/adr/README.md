# Architecture Decision Records (ADR)

This directory contains Architecture Decision Records (ADRs) for QAuth.

## What is an ADR?

An ADR is a document that captures an important architectural decision made along with its context and consequences.

## ADR Index

| ID                                 | Title                       | Status   | Date       |
| ---------------------------------- | --------------------------- | -------- | ---------- |
| [001](./001-jwt-key-management.md) | JWT Key Management Strategy | Accepted | 2026-01-15 |

## ADR Template

When creating a new ADR:

1. Copy the template below
2. Name the file `NNN-short-title.md` (e.g., `002-database-strategy.md`)
3. Fill in the sections
4. Update this index

```markdown
# ADR-NNN: Title

**Status:** Proposed | Accepted | Deprecated | Superseded  
**Date:** YYYY-MM-DD  
**Authors:** Names

## Context

What is the issue that we're seeing that is motivating this decision?

## Decision

What is the change that we're proposing and/or doing?

## Consequences

What becomes easier or more difficult to do because of this change?

### Positive

### Negative

### Neutral

## Related

Links to related ADRs, RFCs, or issues.
```

## References

- [ADR GitHub Organization](https://adr.github.io/)
- [Michael Nygard's article on ADRs](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
