# Merge scan — `gitleaks-merges.sh`

`gitleaks-merges.sh` and `gitleaks.pin` are byte copies from robotico-packages' `packages/dev-hooks/checks/`.
The script scans what merge commits bring themselves (the lines no parent had, which gitleaks' patch scan never
shows). The pin travels beside it because both the script and `actions/gitleaks-pinned` validate the same scanner
version, image digest and Linux x64 archive checksum. `SOURCE.json` records the source commit and both sha256s;
`tests/test_workflows.py` checks the hashes and modes (100755 for the script, 100644 for the pin).
`actions/gitleaks-merges/run.sh` runs the script with exactly one of `image` or `binary`.
Both `actions/gitleaks-merges` and `actions/gitleaks-scan` use that runner; an empty range selects `--all`, while
the scan composite can supply a validated `A..B` range. `actions/gitleaks-pinned/install.sh` supplies the verified
binary to either composite.

dev-hooks is the source: its tests run the scan against real repositories; this repository checks the action wiring
with fake tools and checks the workflow calls.

## Changing the scan

1. Change it in dev-hooks, with its tests, and merge there.
2. Copy both files from that merge commit (`git show <sha>:packages/dev-hooks/checks/<file>`, modes above),
   set `commit` and both sha256s in `SOURCE.json`; once a dev-hooks release carries the commit, `tag` names it.
3. Run this repository's `ci` job; move `v1` only after it is green. A caller sees the change with that move.
