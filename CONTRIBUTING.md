# Contributing

Keep each change focused and include a clear reason for it. Use a feature branch,
run the tests, and open a pull request for review before merging into main.

```bash
git switch -c feature/describe-your-change
.venv/bin/python -m unittest discover -v
git diff --check
git status --short
git add path/to/changed-file
git diff --cached
git commit -m "Describe the resulting behavior"
git push -u origin HEAD
```

Tests should use local fixtures or mocks; never contact third-party scan targets
in automated tests. Preserve existing SQLite records, escape untrusted evidence,
and distinguish missing information from vulnerabilities.

Do not commit databases, credentials, scan exports or virtual environments. The
.gitignore file is a first line of defense, not a substitute for reviewing changes.
