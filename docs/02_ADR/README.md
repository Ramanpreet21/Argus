# ADR Template: Architecture Decision Records

Every major decision should be recorded here. Use this template:

---

## ADR-NNN: [Decision Title]

**Status:** [Proposed | Accepted | Deprecated | Superseded]
**Date:** YYYY-MM-DD
**Author:** Ramanpreet Singh
**Effort to Implement:** [1 day | 2 days | etc.]
**Linked Code:** [file path or PR#]

---

### Context

What problem are we solving? What constraints do we face?

Example:
> We need to send 78 attack payloads to an endpoint. Sequential sending takes 40–60s, which is too slow for real-time demos. Async could reduce to 10–15s, but adds complexity.

---

### Decision

What did we decide to do?

Example:
> Use async dispatch with batch size 5 (5 concurrent requests).

---

### Rationale

Why is this the right choice?

Example:
- **Speed:** 4–6x faster than sequential
- **Fairness:** Batch size prevents overwhelming target
- **Scalability:** Can extend to 200+ payloads without becoming unacceptable
- **Trade-off:** Slightly more complex code (asyncio.gather, exception handling), but worth it

---

### Consequences

What are the downsides or future implications?

Example:
- (+) Much faster scans, demo-friendly
- (+) Naturally handles variable target response times
- (-) Batch size needs tuning per target
- (-) Error handling more complex (aggregate exceptions)
- (?) May need to adjust batch size based on target's 429 responses

---

### Alternatives Considered

What other options did we reject, and why?

Example:
1. **Sequential dispatch:** Simpler code, but too slow (40–60s)
2. **Fixed batch size 10:** Might overwhelm some targets
3. **Dynamic batching:** Too complex for MVP

---

### Follow-Up Questions

- Does async dispatch handle timeouts gracefully? [Answered: Yes, with tenacity]
- Should batch size be configurable? [Answered: Yes, CLI arg --batch-size]
- What happens if target 429s? [Answered: 30s backoff, automatic retry]

---

### Related ADRs

- ADR-002: Why deterministic heuristics (not ML)
- ADR-003: Why YAML payloads (not hardcoded)

---

### Test Coverage

- Test: Async dispatcher respects batch size limit
- Test: 429 response triggers backoff
- Test: Timeout handled gracefully
- Test: All payloads executed (no duplicates, no skips)

---

### Revision History

| Date | Change | Author |
|------|--------|--------|
| 2026-06-24 | Initial decision | Ramanpreet |
| 2026-06-25 | Validated with first dispatcher test | Ramanpreet |
