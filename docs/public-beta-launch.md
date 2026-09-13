# SentinelAI Public Beta Launch Plan

## Beta objective

Validate whether authorized users understand and find value in SentinelAI's bounded
Website, API, Domain and IP observations before building accounts or billing.

## Current release

- Live scanner: https://sentinelai-vn61.onrender.com
- Portfolio page: https://sentinelai-vn61.onrender.com/project
- Beta guide: https://sentinelai-vn61.onrender.com/beta
- Source: https://github.com/JesseDogara/sentinelai

The service is free. It has no customer accounts, permanent storage, payment system,
AI model or paid plan. Public scan history is separated by a browser-session token
but can reset with the temporary Render filesystem.

## Tester invitation

Invite 5–10 people who control a website, API, domain or public IP address. Tell each
tester to assess only a target they own or are explicitly authorized to test. Do not
request private URLs, credentials or copies of confidential reports.

Ask four questions:

1. Which assessment did you try?
2. What did you expect before running it?
3. What result or instruction was unclear?
4. Would you use it again, and for what job?

## Evidence to record

Record facts rather than estimates:

- Number of people personally invited.
- Number who confirmed completing an assessment.
- Assessment types they said they used.
- Repeated usability problems.
- Bugs reproduced and fixed.
- Direct quotes only with the speaker's permission.

Do not call an invitation a user, an opened link a completed scan, or informal praise
a testimonial.

## Gate before accounts and payments

Do not introduce billing merely because the beta is live. Review the next phase after:

- at least five people have completed an authorized test;
- the most common confusing points have been addressed;
- there is a clear reason for permanent user accounts and saved history; and
- at least two testers say they would return or pay for a defined outcome.

These are decision criteria, not claims that the targets have already been achieved.

## Known operational limits

- Render's free service can cold-start after being idle.
- SQLite history is temporary.
- One process limits concurrent scanning and stores rate limits in memory.
- There is no service-level target ownership verification beyond user confirmation.
- Results are observations, not vulnerability confirmations or security certification.

## Next technical phase if validated

1. User registration, login, email verification and account recovery.
2. Managed PostgreSQL with retention and deletion rules.
3. DNS or file-based target ownership verification.
4. Background scan jobs and durable rate/credit tracking.
5. Two free credits per verified account.
6. Paystack test-mode checkout and signed webhook processing.
7. Prepaid credit bundles before recurring subscriptions.
