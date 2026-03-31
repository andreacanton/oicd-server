Run the full quality gate for the current branch before opening or merging a PR.

Steps:
1. Run `bun test` and report pass/fail with a summary of test results.
2. Run `bun run build` and report whether the build succeeded.
3. Run `git diff main...HEAD --stat` to show what files changed.
4. Check that the current branch is NOT `main` (PRs should come from feature branches).
5. Print a final verdict: READY or NOT READY, with details on any failures.

If all checks pass, suggest the `gh pr create` command with the PR template pre-filled.
