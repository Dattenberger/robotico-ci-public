"""The fetch step adopts a workspace seed: warm runs match cold runs, and anything but a valid seed fails.

A seed is built here the way a self-hosted runner leaves one (init without template, origin URL, refs only under
refs/ci-seed/, HEAD detached, working tree checked out, marker .git/ci-seed). All repositories are local fixtures with
harmless finding markers read by the fake scanner.
@see .github/workflows/secret-scan.yml, tests/test_scan_scope.py
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_gitleaks_merges import ROOT, VERSION, load, step_named

GIT_ENV = dict(os.environ, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t',
               GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t',
               GIT_NO_REPLACE_OBJECTS='1')
STEPS = load(ROOT / '.github/workflows/secret-scan.yml')['jobs']['gitleaks']['steps']
SCAN_STEPS = load(ROOT / 'actions/gitleaks-scan/action.yml')['runs']['steps']
MODES = (('pr', 'pull_request'), ('full', 'pull_request'), ('full', 'push'))
REFUSED = '::error::the workspace is not empty and holds no valid seed ('


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(cwd), *args], env=GIT_ENV,
                          check=True, capture_output=True, text=True).stdout.strip()


class GitSeed(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix='rci-seed-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.src = self.tmp / 'src'
        self.src.mkdir()
        git(self.src, 'init', '-q', '-b', 'main')
        self.commit('.gitignore', 'build/\n')
        self.commit('a.txt', 'a\n')
        git(self.src, 'checkout', '-q', '-b', 'side')
        self.commit('side.txt', 'side\n')
        git(self.src, 'tag', 'v0')
        git(self.src, 'checkout', '-q', 'main')
        self.origin = self.tmp / 'owner/repo.git'
        self.origin.parent.mkdir()
        git(self.tmp, 'clone', '-q', '--bare', str(self.src), str(self.origin))
        git(self.origin, 'config', 'uploadpack.allowAnySHA1InWant', 'true')
        git(self.src, 'config', 'uploadpack.allowAnySHA1InWant', 'true')
        self.url = f'file://{self.tmp}/owner/repo.git'

    def commit(self, path: str, text: str, cwd: Path | None = None) -> str:
        cwd = cwd or self.src
        (cwd / path).write_text(text)
        git(cwd, 'add', path)
        git(cwd, 'commit', '-q', '-m', path)
        return git(cwd, 'rev-parse', 'HEAD')

    def push(self) -> None:
        git(self.src, 'push', '-q', '--force', '--all', str(self.origin))
        git(self.src, 'push', '-q', '--force', '--tags', str(self.origin))

    def finding(self, branch: str) -> None:
        """A marker committed and removed again on <branch>: only a history scan finds it."""
        git(self.src, 'checkout', '-q', branch)
        self.commit('finding.txt', 'scan-fixture-finding\n')
        git(self.src, 'rm', '-q', 'finding.txt')
        git(self.src, 'commit', '-q', '-m', 'remove fixture')
        git(self.src, 'checkout', '-q', 'main')

    def make_seed(self, name: str = 'warm', extra: dict | None = None) -> Path:
        """A seed of origin's main as the runner leaves it; <extra> adds refs/ci-seed/heads/<n> = <sha> (stale)."""
        ws = self.tmp / name
        git(self.tmp, 'init', '-q', '--template=', str(ws))
        git(ws, 'config', 'remote.origin.url', self.url)
        git(ws, 'config', 'gc.auto', '0')
        git(ws, 'fetch', '-q', self.url, '+refs/heads/main:refs/ci-seed/heads/main')
        for ref, sha in (extra or {}).items():
            git(ws, 'fetch', '-q', str(self.src), sha)
            git(ws, 'update-ref', f'refs/ci-seed/heads/{ref}', sha)
        head = git(ws, 'rev-parse', 'refs/ci-seed/heads/main')
        git(ws, 'update-ref', '--no-deref', 'HEAD', head)
        git(ws, 'reset', '-q', '--hard')
        git(ws, 'update-index', '-q', '--refresh')
        (ws / '.git/ci-seed').write_text('v=1\nrepo=owner/repo.git\nrepacked=1700000000\n')
        return ws

    def event(self, history: str, event: str) -> dict:
        """The event values: a PR from 'pr' into main whose event commit is the synthetic merge."""
        main = git(self.src, 'rev-parse', 'main')
        env = dict(RCI_HISTORY=history, RCI_EVENT=event, RCI_SHA=main, RCI_BASE='', RCI_HEAD='',
                   RCI_DEFAULT_BRANCH='main')
        if event == 'pull_request':
            head = git(self.src, 'rev-parse', 'pr')
            merge = subprocess.run(['git', '-C', str(self.origin), 'commit-tree', f'{head}^{{tree}}', '-p', main,
                                    '-p', head, '-m', 'pr merge'], env=GIT_ENV, check=True, capture_output=True,
                                   text=True).stdout.strip()
            git(self.origin, 'update-ref', 'refs/pull/1/merge', merge)
            env.update(RCI_SHA=merge, RCI_BASE=main, RCI_HEAD=head)
        return env

    def step(self, name: str, ws: Path, env: dict) -> subprocess.CompletedProcess:
        full = dict(GIT_ENV, RCI_TOKEN='t0ken', RCI_SERVER=f'file://{self.tmp}', RCI_REPO='owner/repo.git',
                    GITHUB_OUTPUT=str(ws.parent / f'{ws.name}.output'))
        full.update(env)
        command = ['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', step_named(STEPS, name)['run']]
        return subprocess.run(command, cwd=ws, env=full, capture_output=True, text=True)

    def fetch(self, ws: Path, **env: str) -> subprocess.CompletedProcess:
        return self.step('Fetch history', ws, dict(self.event('full', 'push'), **env))

    def run_job(self, ws: Path, env: dict) -> dict:
        """Fetch, select and both scans as the workflow runs them; everything a verdict depends on."""
        for name in ('Fetch history', 'Select history'):
            result = self.step(name, ws, env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        selected = dict(line.split('=', 1) for line in (ws.parent / f'{ws.name}.output').read_text().splitlines())
        scanned = ws.parent / f'{ws.name}.scanned'
        scan_env = dict(GIT_ENV, GITHUB_WORKSPACE=str(ws), GITHUB_ACTION_PATH=str(ROOT / 'actions/gitleaks-scan'),
                        RCI_BINARY=str(ROOT / 'tests/fakebin/gitleaks'), RCI_IMAGE='', RCI_CONFIG='',
                        RCI_RANGE=selected.get('range', ''), RCI_REVISIONS=selected.get('revisions', ''),
                        FAKE_SCOPE_SCAN='1', FAKE_PINNED_VERSION=VERSION,
                        FAKE_GITLEAKS_ARGS=str(ws.parent / f'{ws.name}.args'), FAKE_SCANNED_REVISIONS=str(scanned))
        verdicts = []
        for name in ('gitleaks (history)', "gitleaks over the merges' own content"):
            result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c',
                                     step_named(SCAN_STEPS, name)['run']], cwd=ws, env=scan_env,
                                    capture_output=True, text=True)
            verdicts.append((result.returncode, 'found potential secrets' in result.stdout))
        return {'refs': git(ws, 'for-each-ref', '--format=%(objectname) %(refname)'),
                'all': sorted(git(ws, 'rev-list', '--all').split()), 'head': git(ws, 'rev-parse', 'HEAD'),
                'selected': selected, 'scanned': sorted(scanned.read_text().split()), 'verdicts': verdicts,
                'status': git(ws, 'status', '--porcelain', '--ignored'),
                'remote': sorted(git(ws, 'config', '--local', '--get-regexp', '^remote\\.').splitlines())}

    def assert_warm_equals_cold(self, extra: dict | None = None, finding: tuple = ()) -> None:
        """Per mode, cold (empty workspace) and warm (seed) runs agree; modes in <finding> fail on a finding."""
        for history, event in MODES:
            with self.subTest(history=history, event=event):
                tag = f'{history}-{event}'
                cold = self.tmp / f'cold-{tag}'
                cold.mkdir()
                warm = self.make_seed(f'warm-{tag}', extra)
                env = self.event(history, event)
                expected = self.run_job(cold, env)
                self.assertEqual(self.run_job(warm, env), expected)
                self.assertEqual(expected['verdicts'],
                                 [(1, True), (0, False)] if (history, event) in finding else [(0, False)] * 2)
                self.assertNotIn('refs/ci-seed/', expected['refs'])


class WarmEqualsCold(GitSeed):
    def setUp(self) -> None:
        super().setUp()
        git(self.src, 'checkout', '-q', '-b', 'pr')
        self.commit('pr.txt', 'pr\n')
        git(self.src, 'checkout', '-q', 'main')
        self.push()

    def test_a_current_seed_gives_the_cold_refs_revisions_and_verdicts(self) -> None:
        self.assert_warm_equals_cold()

    def test_a_stale_seed_fetches_what_the_target_added(self) -> None:
        """The seed predates the new main commits and a finding on the PR branch; both reach the scan."""
        stale = {'old': git(self.src, 'rev-parse', 'main')}
        self.commit('b.txt', 'b\n')
        self.finding('pr')
        self.push()
        self.assert_warm_equals_cold(extra=stale, finding=MODES)

    def test_a_seed_ref_to_a_commit_gone_from_the_target_is_not_scanned(self) -> None:
        """A branch force-pushed away after seeding left a finding only the seed still holds."""
        git(self.src, 'checkout', '-q', '-b', 'gone', 'main')
        self.finding('gone')
        gone = git(self.src, 'rev-parse', 'gone')
        git(self.src, 'branch', '-q', '-D', 'gone')
        self.assert_warm_equals_cold(extra={'gone': gone})
        warm = self.tmp / 'warm-full-push'
        self.assertEqual(git(warm, 'cat-file', '-t', gone), 'commit')

    def test_a_finding_on_the_default_branch_fails_warm_and_cold(self) -> None:
        """The PR range base..head excludes the default branch's history in both runs."""
        self.finding('main')
        self.push()
        self.assert_warm_equals_cold(finding=MODES[1:])


class SeedShape(GitSeed):
    def setUp(self) -> None:
        super().setUp()
        self.push()

    def assert_adopted(self, ws: Path) -> None:
        result = self.fetch(ws)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(git(ws, 'rev-parse', 'HEAD'), git(self.src, 'rev-parse', 'main'))
        self.assertEqual(git(ws, 'for-each-ref', '--format=%(refname)', 'refs/ci-seed/'), '')
        self.assertNotIn('t0ken', (ws / '.git/config').read_text())

    def assert_refused(self, ws: Path, reason: str, **env: str) -> None:
        result = self.fetch(ws, **env)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f'{REFUSED}{reason})', result.stdout)
        self.assertFalse((ws / '.git/refs/remotes').exists())
        self.assertNotIn('t0ken', (ws / '.git/config').read_text() if (ws / '.git/config').is_file() else '')

    def test_a_valid_seed_with_an_empty_hooks_dir_or_a_prepared_ref_is_adopted(self) -> None:
        self.assert_adopted(self.make_seed())
        ws = self.make_seed('prepared')
        (ws / '.git/hooks').mkdir()
        main = git(ws, 'rev-parse', 'HEAD')
        git(ws, 'update-ref', 'refs/ci-seed/prepared', main)
        git(ws, 'pack-refs', '--all')
        with (ws / '.git/ci-seed').open('a') as marker:
            marker.write(f'prepared={main}\n')
        self.assert_adopted(ws)

    def test_a_missing_or_forged_marker_is_refused(self) -> None:
        cases = {'missing': None, 'version': 'v=2\nrepo=owner/repo.git\nrepacked=1\n',
                 'foreign repo': 'v=1\nrepo=owner/other.git\nrepacked=1\n', 'no repacked': 'v=1\nrepo=owner/repo.git\n',
                 'extra line': 'v=1\nrepo=owner/repo.git\nrepacked=1\nx=1\n',
                 'twice': 'v=1\nrepo=owner/repo.git\nrepo=owner/repo.git\nrepacked=1\n',
                 'prepared': 'v=1\nrepo=owner/repo.git\nrepacked=1\nprepared=main\n',
                 'oversized': 'v=1\nrepo=owner/repo.git\nrepacked=1\n' + 'repacked=1\n' * 100}
        for n, (case, text) in enumerate(cases.items()):
            with self.subTest(case=case):
                ws = self.make_seed(f'marker-{n}')
                if text is None:
                    (ws / '.git/ci-seed').unlink()
                else:
                    (ws / '.git/ci-seed').write_text(text)
                self.assert_refused(ws, 'no marker' if case in ('missing', 'oversized') else 'malformed marker')

    def test_a_seed_spelling_the_repository_in_another_case_is_adopted(self) -> None:
        """GitHub names are case-insensitive; the fetch then uses the repository's own spelling of the URL."""
        ws = self.make_seed('case')
        git(ws, 'config', 'remote.origin.url', f'file://{self.tmp}/OWNER/Repo.git')
        (ws / '.git/ci-seed').write_text('v=1\nrepo=OWNER/Repo.git\nrepacked=1\n')
        self.assert_adopted(ws)
        self.assertEqual(git(ws, 'config', 'remote.origin.url'), self.url)
        ws = self.make_seed('case-other')
        git(ws, 'config', 'remote.origin.url', f'file://{self.tmp}/OWNER/Other.git')
        self.assert_refused(ws, 'origin is another repository')
        ws = self.make_seed('case-other-marker')
        (ws / '.git/ci-seed').write_text('v=1\nrepo=OWNER/Other.git\nrepacked=1\n')
        self.assert_refused(ws, 'malformed marker')

    def test_a_seed_of_another_repository_is_refused(self) -> None:
        ws = self.make_seed('other-url')
        git(ws, 'config', 'remote.origin.url', f'file://{self.tmp}/owner/other.git')
        self.assert_refused(ws, 'origin is another repository')
        ws = self.make_seed('two-urls')
        git(ws, 'config', '--add', 'remote.origin.url', self.url)
        self.assert_refused(ws, 'origin is another repository')
        ws = self.make_seed('no-url')
        git(ws, 'config', '--unset', 'remote.origin.url')
        self.assert_refused(ws, 'origin is another repository')

    def test_config_outside_the_allowed_keys_is_refused(self) -> None:
        for n, (key, value) in enumerate((('http.extraheader', 'AUTHORIZATION: basic x'), ('include.path', 'x'),
                                          ('core.fsmonitor', 'true'), ('core.sshCommand', 'touch canary'),
                                          ('remote.origin.fetch', '+refs/*:refs/*'))):
            with self.subTest(key=key):
                ws = self.make_seed(f'config-{n}')
                git(ws, 'config', key, value)
                self.assert_refused(ws, 'config key outside the allowed set')
        ws = self.make_seed('bare')
        git(ws, 'config', 'core.bare', 'true')
        self.assert_refused(ws, 'bare repository')

    def test_hooks_are_refused_and_never_run(self) -> None:
        ws = self.make_seed('hooks')
        hook = ws / '.git/hooks/reference-transaction'
        hook.parent.mkdir()
        hook.write_text(f'#!/bin/sh\ntouch {self.tmp}/canary\n')
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
        self.assert_refused(ws, 'hooks')
        self.assertFalse((self.tmp / 'canary').exists())

    def test_alternates_shallow_history_and_links_are_refused(self) -> None:
        ws = self.make_seed('alternates')
        (ws / '.git/objects/info/alternates').write_text(f'{self.origin}/objects\n')
        self.assert_refused(ws, 'alternates')
        ws = self.make_seed('shallow')
        (ws / '.git/shallow').write_text(git(ws, 'rev-parse', 'HEAD') + '\n')
        self.assert_refused(ws, 'unexpected entry in .git')
        for n, path in enumerate(('info/attributes', 'info/grafts', 'description', 'commondir')):
            with self.subTest(path=path):
                ws = self.make_seed(f'entry-{n}')
                (ws / '.git' / path).parent.mkdir(exist_ok=True)
                (ws / '.git' / path).write_text('* -diff\n')
                self.assert_refused(ws, 'unexpected entry in .git/info' if path.startswith('info/')
                                    else 'unexpected entry in .git')
        ws = self.make_seed('link')
        (ws / '.git/objects/info/packs').symlink_to(self.origin / 'objects/info')
        self.assert_refused(ws, 'link in .git')
        ws = self.tmp / 'git-link'
        ws.mkdir()
        (ws / '.git').symlink_to(self.make_seed('target') / '.git')
        self.assert_refused(ws, 'no .git directory')

    def test_refs_outside_the_seed_namespace_are_refused(self) -> None:
        for n, ref in enumerate(('refs/heads/main', 'refs/tags/t', 'refs/remotes/origin/main', 'refs/stash')):
            for packed in (False, True):
                with self.subTest(ref=ref, packed=packed):
                    ws = self.make_seed(f'ref-{n}-{packed}')
                    git(ws, 'update-ref', ref, 'HEAD')
                    if packed:
                        git(ws, 'pack-refs', '--all')
                    result = self.fetch(ws)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(f'{REFUSED}ref outside refs/ci-seed/)', result.stdout)
        ws = self.make_seed('attached')
        git(ws, 'symbolic-ref', 'HEAD', 'refs/ci-seed/heads/main')
        self.assert_refused(ws, 'HEAD is not detached at a commit')

    def test_files_beside_the_seed_are_refused(self) -> None:
        for n, (path, text) in enumerate((('leftover', 'x'), ('.gitleaks.toml', '[allowlist]\n'), ('a.txt', 'b\n'),
                                          ('build/out', 'x'), ('.ci-seed-other/.git/ci-seed', 'v=1\n'),
                                          ('deep/er/.git', 'gitdir: elsewhere\n'))):
            with self.subTest(path=path):
                ws = self.make_seed(f'beside-{n}')
                (ws / path).parent.mkdir(parents=True, exist_ok=True)
                (ws / path).write_text(text)
                # git status never lists a path below a .git component, so those get their own check.
                self.assert_refused(ws, 'nested repository' if '.git' in Path(path).parts
                                    else 'files beside the seed or changed')
        for n, flag in enumerate(('--assume-unchanged', '--skip-worktree')):
            with self.subTest(flag=flag):
                ws = self.make_seed(f'flag-{n}')
                git(ws, 'update-index', flag, 'a.txt')
                (ws / 'a.txt').write_text('hidden\n')
                self.assert_refused(ws, 'index flags')

    def test_a_seed_owned_by_another_user_is_refused(self) -> None:
        """A fake id makes the runner another uid than the files' owner, without root or user namespaces."""
        fakebin = self.tmp / 'fakebin'
        fakebin.mkdir()
        fake_id = fakebin / 'id'
        fake_id.write_text(f'#!/bin/sh\n[ "$1" = -u ] && {{ echo {os.getuid() + 1}; exit 0; }}\nexec /usr/bin/id "$@"\n')
        fake_id.chmod(0o755)
        ws = self.make_seed('foreign-owner')
        self.assert_refused(ws, 'not owned by the runner user', PATH=f"{fakebin}:{os.environ['PATH']}")
        self.assert_adopted(ws)


if __name__ == '__main__':
    unittest.main()
