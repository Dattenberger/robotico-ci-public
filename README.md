# robotico-ci-public

Public CI building blocks of Robotico. Repositories of the `Dattenberger` organisation run them through an
organisation ruleset; the private `robotico-ci` builds its own workflows on top of them.

The secret scan runs the pinned gitleaks binary over git history, then scans the content merge commits bring
themselves (which the ordinary patch scan misses). A finding or an incomplete scan fails the job. The installer
reuses a binary of the pinned version or downloads the Linux x64 release and verifies its checksum; no Docker is
needed. Standalone merge scans can also use the pinned Docker image.

Configure an organisation ruleset of type `workflows` to require
`.github/workflows/secret-scan.yml` from this repository at `v1`. It runs on every pull request, scanning
`base.sha..head.sha` in the target repository with only `contents: read`. The full-history nightly sweep belongs
in `robotico-ci`. Runners use `vars.CI_RUNS_ON_S || 'ubuntu-latest'`; the organisation variable is private-only, so
public repositories and fork PRs use GitHub-hosted runners.

For a reusable full-history scan:

```yaml
jobs:
  secrets:
    permissions:
      contents: read
    uses: Dattenberger/robotico-ci-public/.github/workflows/secret-scan.yml@v1
    with:
      history: full
```

`history` defaults to `full`. Set it to `pr` to scan the PR range in a calling workflow triggered by
`pull_request`; other events fail with that setting. Direct PR runs of the required workflow always select the PR
range. On a `pull_request` event, a reusable `history: full` call scans the union of the repository's default
branch history and the PR head's history, including findings removed by later commits. Commits reachable only
from other branches or tags are excluded. The default branch is the repository's configured default, even when
the PR targets another branch. The workflow fetches only that branch, the PR head and the event commit (the PR
merge commit) with complete histories, and checks out the event commit, so `.gitleaks.toml` and `.gitleaksignore`
come from the merged tree as in every other mode. The synthetic PR merge commit itself is outside the scanned
selection; actual merges in either selected history are scanned for their own content.

Other events using `history: full` retain the all-branch, all-tag scan and checkout of the event commit.
The `pr` mode keeps its `base.sha..head.sha` selection and existing fetch behaviour.
The workflow fetches with plain git rather than `actions/checkout`, whose credential cleanup fails on a gitlink
that has no `.gitmodules` entry.
It needs an empty workspace, so it runs only on ephemeral runners (the CI pool, GitHub-hosted).

To use the composite directly, check out the target repository with `fetch-depth: 0` and
`persist-credentials: false`, then call `Dattenberger/robotico-ci-public/actions/gitleaks-scan@v1`.
Its optional `range` input accepts exactly two lowercase 40-character commit SHAs separated by `..`. Its optional `revisions` input accepts one or more lowercase 40-character commit SHAs separated
by single spaces, scanning the union of their reachable histories. It is mutually exclusive with `range`;
leaving both empty preserves the all-ref scan. For a full PR scan, supply the default-branch tip and PR head SHA
after fetching their complete histories. Both the history and merge scans use the same selection.
The standalone `actions/gitleaks-merges` composite also accepts optional `revisions`; leaving it empty retains
its all-ref scan. Its existing `binary` and `image` inputs keep their meaning.

Without a `config` input both scans use the target checkout's own `.gitleaks.toml` (a regular file at its root)
when present, as dev-hooks does locally; otherwise the history scan uses the one shipped here and the merge scan the
built-in rules. A supplied config path resolves from the checkout.

**Known limits:** a repository's own `.gitleaks.toml` can narrow both scans; robotico-ci's repo-standard keeps the
copies byte-identical to the shared one.
The scan catches accidental leaks; it is no control against an author who suppresses a finding on purpose
(`.gitleaksignore` and `gitleaks:allow` comments in the scanned tree are honoured). No merge queue support yet
(`merge_group` trigger missing): a repository that enables a merge queue needs it first. Both scans refuse shallow checkouts,
grafts and symlinks in the git directory, ignore replace refs, and disable repository diff drivers. Merge findings have no commit fingerprint; allowances
belong in the target checkout's `.gitleaks.toml`. Binary merge content is outside the patch scanner's coverage.

The source and update procedure are in [contract/gitleaks-merges/README.md](contract/gitleaks-merges/README.md):
change the scan in dev-hooks first, then copy it here. The contract script, pin, provenance and `.gitleaks.toml`
are byte copies; comments in those copies retain their source context. The two standalone composites share
`install.sh` and `run.sh` with `gitleaks-scan`, so callers never need nested action references.

Run `python3 -m unittest discover -s tests -t .` for offline unittest tests with fake tools and the copied safe
YAML loader (PyYAML, supplied by the supported runners), and `bash -n` on every `.sh` file. This repository's `ci`
job runs the unit tests and the local composite over its full history, so a PR tests its own action tree. Move the
`v1` tag only after a green `ci` run.

When releasing a new composite input, publish the composite first and move `v1` after its checks pass. Publish
the reusable workflow change that passes that input only after the tag includes the composite support.
