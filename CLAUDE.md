# CLAUDE.md — robotico-ci-public

The public half of Robotico's CI: building blocks that every repository of the organisation, public ones included,
may run. Today that is the secret scan (gitleaks). Everything that needs internal names, tokens or reports stays in the
private `robotico-ci`.

<!-- toc -->
**Contents**

- [Data classes and trust levels](#data-classes-and-trust-levels)
- [Verification](#verification)
<!-- /toc -->

## Data classes and trust levels

Level: public (set by Lukas on 2026-11-08, repository created as robotico-ci-public). Extensions: none.
Before every commit, read robotico-core:data-classes: what may be committed here and, above all, what may not.
Nothing internal goes here: no hostnames, internal URLs, people, customer or business data, no ticket texts.

## Verification

- **Delivery:** pull request to `main`; read the required `ci` result on the head before merge. Follow
  [README.md](README.md) for publication order and advancing `v1` only after a green CI run.
- **Full check:** the `ci` job in `.github/workflows/ci.yml`, once on the pull request head: offline unit tests
  and the checked-out local composite's full-history scan. Locally only affected tests and quick checks.

| What | How | Where | Required when |
|---|---|---|---|
| Affected unit tests | `python3 -m unittest tests.<module>` (offline; PyYAML needed) | development host | the corresponding scripts, action/workflow contracts or fixtures changed |
| Shell syntax | `bash -n` on every `.sh` file, as documented in README; the full shell-syntax check described in README is not wired into `ci.yml` as a separate step | development host | shell files changed |
| Full check | `ci`: `python3 -m unittest discover -s tests -t .`, then `./actions/gitleaks-scan` over the full history | PR CI | every change |

Every change runs the rows it touches before its pull request, merge and publication, and no more. The evidence
(command, result and SHA) goes into the pull request body.
