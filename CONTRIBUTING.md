# Contributing

Welcome! This is an educational OIDC server, and contributions of all kinds are appreciated — whether it's a bug report, a feature idea, documentation improvements, or code. Every contribution helps make this a better learning resource.

## Table of Contents

- [Important Resources](#important-resources)
- [Project Setup](#project-setup)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Submitting Changes](#submitting-changes)
- [Quality Gate](#quality-gate)
- [What to Include in a PR](#what-to-include-in-a-pr)
- [Style Guide](#style-guide)
- [Getting Help](#getting-help)
- [Recognition](#recognition)

## Important Resources

- [README.md](README.md) — project overview and getting started
- [CLAUDE.md](CLAUDE.md) — architecture, endpoints, and crypto details
- [GitHub Issues](../../issues) — bug reports and feature requests

## Project Setup

```bash
bun install
bun run dev    # start dev server on port 3000
bun test       # run test suite
```

See [CLAUDE.md](CLAUDE.md) for full architecture details.

## How to Contribute

### Reporting Bugs

Found something broken? [Open a bug report](../../issues/new?template=bug_report.md) and include:

- **What you expected** to happen
- **What actually happened**
- **Steps to reproduce** the issue
- Your environment (OS, Bun version)

### Suggesting Enhancements

Have an idea for a new feature or improvement? [Open an enhancement request](../../issues/new?template=enhancement.md) and:

- Describe the **use case** — what problem does it solve?
- Explain your **proposed solution**
- Label it as an enhancement if possible

### Submitting Changes

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

## Style Guide

There is no linter configured. Follow these conventions:

- **TypeScript** — all source code is in `src/`
- **Zero external dependencies** — use Node.js built-in `crypto` and Bun APIs only
- **Follow existing patterns** — read `src/index.ts` and match the style you see there
- **Keep it simple** — this is an educational project; clarity beats cleverness

## Getting Help

Stuck or have a question? Open a [GitHub Issue](../../issues/new) — there are no bad questions.

## Recognition

Contributors are acknowledged in PR merge commits. Thank you for helping improve this project!
