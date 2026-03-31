# Contributing

Thank you for your interest in contributing to this OIDC server! This document describes the workflow and quality standards for all contributions.

## Branch Workflow

This project follows **GitHub Flow**. The `main` branch is protected — all changes go through pull requests.

1. **Create a branch** from `main` with a flat, descriptive name:
   ```bash
   git checkout main && git pull
   git checkout -b fix-token-expiry
   ```
   Use lowercase-hyphenated names. Do **not** use folder prefixes like `feat/`, `fix/`, `docs/`.

2. **Make your changes.** Keep PRs focused — one logical change per PR.

3. **Run the quality gate locally** before pushing (see below).

4. **Open a pull request** to `main`. Fill out the PR template completely.

5. **Address review feedback**, then the PR gets merged.

## Quality Gate

Every PR must pass these checks before merge:

| Check | Command | Expectation |
|-------|---------|-------------|
| Tests pass | `bun test` | All tests green, no regressions |
| Build succeeds | `bun run build` | Clean build to `./dist` |
| Self-review | — | You have re-read your own diff |
| PR template | — | All sections of the PR template are filled out |

Run both checks locally in one go:

```bash
bun test && bun run build
```

## What to Include in a PR

- **Focused scope**: one feature, one bugfix, or one refactor. Don't mix concerns.
- **Tests**: if you add or change behavior, add or update tests in `src/index.test.ts`.
- **No unrelated changes**: avoid drive-by formatting fixes or refactors in the same PR.

## Project Setup

```bash
bun install
bun run dev    # start dev server on port 3000
bun test       # run test suite
```

See [CLAUDE.md](CLAUDE.md) for full architecture details.
