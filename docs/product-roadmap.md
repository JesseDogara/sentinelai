# SentinelAI product roadmap

## Shipped in the Domain/IP milestone

- Four deliberately scoped assessment types.
- Saved evidence, explanations, target filters and portable reports.
- Query/time limits, input validation and clear error outcomes.
- Regression coverage of existing and new behavior.

## Next quality milestones

1. **Runtime and application hardening:** supported Python/OpenSSL, environment
   configuration, CSRF protection, local origin
   checks and safer website request/body limits. Validate startup and upgrade paths.
2. **Evidence quality:** explicit expected policies per owned asset, contextual
   website scoring, policy comparisons and scan-to-scan differences. Avoid claiming
   a change is a vulnerability without validation.
3. **Workflow:** named projects, asset scope lists, cancellation/background jobs,
   retention controls and consent-aware retesting. Validate scope before every job.
4. **API depth:** user-provided OpenAPI parsing and explicitly configured test
   credentials; strict redaction and limited request budgets. No guessed endpoints
   or unbounded automation.
5. **Assisted explanations:** optional model integration with untrusted evidence
   isolation, citations to observed fields and no authority to launch tools from
   target-provided text. Label suggestions separately from scanner facts.

## Release acceptance criteria

- Existing records survive migration and existing modules retain their behavior.
- Every observation has understandable evidence and a stated assessment limit.
- Failure, missing evidence and confirmed observations are distinct.
- Tests cover meaningful regressions, not just matching implementation details.
- Local verification includes input, result, saved history and report downloads.
- No claims of production readiness or confirmed vulnerabilities without evidence.
