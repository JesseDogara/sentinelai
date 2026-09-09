# Git and GitHub: the working routine

Git records versions on your Mac. GitHub stores a remote copy and provides review,
automated checks and collaboration. Uploading the code does not host the Flask app.

The initial repository is private. Keep it private while learning and completing
the hardening roadmap. A license has deliberately not been selected for this
private milestone; decide how others may reuse the code before a public release.

## After making a change

1. Create a feature branch before editing: `git switch -c feature/short-name`.
2. Run `.venv/bin/python -m unittest discover -v`.
3. Inspect `git status` and `git diff`. Never include private scan data or secrets.
4. Stage only the intended files with `git add <path>`.
5. Check `git diff --cached`, then commit with a clear description.
6. Push the branch with `git push -u origin HEAD`.
7. Open a pull request on GitHub. Review the diff and wait for Tests to pass.
8. Merge when ready, then update the local main branch with `git pull --ff-only`.

The Tests workflow runs on pushes to main and pull requests. Dependabot proposes
monthly Python-package and GitHub Actions updates. Review its pull requests and
keep tests passing; these checks do not replace a security review.

## Protect the account and repository

Use two-factor authentication for your GitHub account. Store recovery codes
privately. Use GitHub CLI, GitHub Desktop or a credential manager to sign in;
never paste access tokens into chat or commit them. Authentication and account
security settings may require you to complete the sign-in yourself.

Git is not a backup of ignored scan history. Back up sentinelai.db separately to
a private location if that history matters. Avoid reinitializing Git inside an
existing clone, and never force-push main just to resolve a sync problem.

Before going public, review every committed file and the full Git history, choose
an appropriate license, confirm dependency notices, verify a clean installation,
and describe limitations accurately. Screenshots should use sample/local targets.
