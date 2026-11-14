"""Exercise revision scope against local histories, with harmless finding markers.

The fake scanner reads real patches and merge trees; all fixtures are invented.
@see README.md, tests/fakebin/gitleaks
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_gitleaks_merges import ROOT, VERSION, load, step_named


class ScanScope(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix='scan-scope-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / 'repo'
        self.repo.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1',
                        GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
                        GIT_COMMITTER_EMAIL='t@t', GIT_NO_REPLACE_OBJECTS='1')
        self.git('init', '-q', '-b', 'trunk')
        self.commit('root.txt', 'root\n')
        self.root = self.git('rev-parse', 'HEAD')
        self.tips = {}
        self.merges = {}
        for branch in ('trunk', 'pr', 'other'):
            self.git('checkout', '-q', '-B', branch, self.root)
            self.commit(f'{branch}.txt', f'{branch}\n')
            self.git('checkout', '-q', '-b', f'{branch}-parent', self.root)
            self.commit(f'{branch}-parent.txt', 'parent\n')
            self.git('checkout', '-q', branch)
            self.git('merge', '-q', '--no-ff', '--no-commit', f'{branch}-parent')
            self.commit(f'{branch}-merge.txt', f'{branch} merge content\n')
            self.merges[branch] = self.git('rev-parse', 'HEAD')
            self.tips[branch] = self.merges[branch]
        self.git('checkout', '-q', 'pr')
        self.binary = ROOT / 'tests/fakebin/gitleaks'
        self.base_env = dict(self.env, GITHUB_WORKSPACE=str(self.repo),
                             GITHUB_ACTION_PATH=str(ROOT / 'actions/gitleaks-scan'),
                             RCI_BINARY=str(self.binary), RCI_IMAGE='', RCI_CONFIG='', RCI_RANGE='',
                             RCI_REVISIONS='', FAKE_SCOPE_SCAN='1', FAKE_PINNED_VERSION=VERSION,
                             FAKE_GITLEAKS_ARGS=str(self.tmp / 'args'),
                             FAKE_SCANNED_REVISIONS=str(self.tmp / 'scanned'))

    def git(self, *args: str) -> str:
        return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(self.repo), *args],
                              env=self.env, capture_output=True, text=True, check=True).stdout.strip()

    def commit(self, path: str, text: str) -> None:
        (self.repo / path).write_text(text)
        self.git('add', path)
        self.git('commit', '-q', '-m', 'fixture')

    def finding(self, branch: str, merge: bool = False) -> None:
        self.git('checkout', '-q', branch)
        if merge:
            (self.repo / f'{branch}-merge.txt').write_text('scan-fixture-finding\n')
            self.git('add', f'{branch}-merge.txt')
            self.git('commit', '-q', '--amend', '--no-edit')
            self.merges[branch] = self.git('rev-parse', 'HEAD')
        else:
            # Removed from the tip: only a history scan can find this marker.
            self.commit('finding.txt', 'scan-fixture-finding\n')
            self.git('rm', '-q', 'finding.txt')
            self.git('commit', '-q', '-m', 'remove fixture')
        self.tips[branch] = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-q', 'pr')

    def scan(self, merges: bool = False, workspace: Path | None = None, **env: str) -> subprocess.CompletedProcess:
        action = load(ROOT / 'actions/gitleaks-scan/action.yml')
        name = "gitleaks over the merges' own content" if merges else 'gitleaks (history)'
        script = step_named(action['runs']['steps'], name)['run']
        return subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
                              cwd=workspace or self.repo,
                              env=dict(self.base_env, GITHUB_WORKSPACE=str(workspace or self.repo), **env),
                              capture_output=True, text=True)

    def selected(self) -> str:
        return f"{self.tips['trunk']} {self.tips['pr']}"

    def test_explicit_tips_exclude_other_branches_from_both_scans(self) -> None:
        self.finding('other', merge=True)
        self.finding('other')
        for merges in (False, True):
            with self.subTest(merges=merges):
                result = self.scan(merges, RCI_REVISIONS=self.selected())
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if merges:
                    self.assertIn('2 merge(s)', result.stdout)
                    self.assertNotIn(self.merges['other'], result.stdout)
                else:
                    actual = set((self.tmp / 'scanned').read_text().splitlines())
                    expected = set(self.git('rev-list', *self.selected().split()).splitlines())
                    self.assertEqual(actual, expected)
                    self.assertIn(self.root, actual)
                    self.assertIn(self.tips['trunk'], actual)
                    self.assertIn(self.tips['pr'], actual)
                    self.assertNotIn(self.tips['other'], actual)

    def assert_finding_fails(self, branch: str, merges: bool = False) -> None:
        self.finding(branch, merge=merges)
        result = self.scan(merges, RCI_REVISIONS=self.selected())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('found potential secrets', result.stdout)

    def test_default_history_finding_fails(self) -> None:
        self.assert_finding_fails('trunk')

    def test_pr_history_finding_fails(self) -> None:
        self.assert_finding_fails('pr')

    def test_default_merge_finding_fails(self) -> None:
        self.assert_finding_fails('trunk', merges=True)

    def test_pr_merge_finding_fails(self) -> None:
        self.assert_finding_fails('pr', merges=True)

    def test_pr_range_still_excludes_default_and_other_history(self) -> None:
        self.finding('trunk')
        self.finding('other', merge=True)
        selected = f"{self.root}..{self.tips['pr']}"
        for merges in (False, True):
            result = self.scan(merges, RCI_RANGE=selected)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.finding('pr')
        result = self.scan(RCI_RANGE=f"{self.root}..{self.tips['pr']}")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_omitting_selection_still_scans_all_refs(self) -> None:
        self.finding('other', merge=True)
        self.finding('other')
        for merges in (False, True):
            result = self.scan(merges)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('found potential secrets', result.stdout)

    def test_invalid_or_conflicting_revisions_fail_before_scanning(self) -> None:
        a = self.tips['trunk']
        for revisions in ('--all', 'trunk pr', a.upper(), f'{a}\n', f' {a}', f'{a}  {a}',
                          f'{a};touch injected', '$(touch injected)'):
            for merges in (False, True):
                with self.subTest(revisions=revisions, merges=merges):
                    result = self.scan(merges, RCI_REVISIONS=revisions)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn('invalid revisions', result.stdout)
                    self.assertFalse((self.tmp / 'args').exists())
        for merges in (False, True):
            result = self.scan(merges, RCI_REVISIONS=self.selected(), RCI_RANGE=f'{self.root}..{a}')
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('range and revisions', result.stdout)
        self.assertFalse((self.repo / 'injected').exists())

    def test_missing_revision_is_no_verdict(self) -> None:
        for merges in (False, True):
            result = self.scan(merges, RCI_REVISIONS=f"{self.tips['trunk']} {'0' * 40}")
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertFalse((self.tmp / 'args').exists())

    def full_pr_workflow(self) -> tuple[Path, str]:
        origin = self.tmp / 'owner/repo.git'
        origin.parent.mkdir()
        self.git('clone', '-q', '--bare', str(self.repo), str(origin))
        workspace = self.tmp / 'workspace'
        workspace.mkdir()
        output = self.tmp / 'output'
        env = dict(self.env, RCI_HISTORY='full', RCI_EVENT='pull_request',
                   RCI_BASE=self.tips['other'], RCI_HEAD=self.tips['pr'], RCI_SHA=self.tips['pr'],
                   RCI_DEFAULT_BRANCH='trunk', RCI_TOKEN='fixture', RCI_SERVER=f'file://{self.tmp}',
                   RCI_REPO='owner/repo.git', GITHUB_OUTPUT=str(output))
        steps = load(ROOT / '.github/workflows/secret-scan.yml')['jobs']['gitleaks']['steps']
        for name in ('Fetch history', 'Select history'):
            result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail',
                                     '-c', step_named(steps, name)['run']],
                                    cwd=workspace, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        selected = dict(line.split('=', 1) for line in output.read_text().splitlines())
        self.assertEqual(selected, {'range': '', 'revisions': self.selected()})
        return workspace, selected['revisions']

    def test_full_pr_workflow_excludes_foreign_findings_from_both_scans(self) -> None:
        self.finding('other', merge=True)
        self.finding('other')
        self.git('tag', 'foreign-only', self.tips['other'])
        workspace, revisions = self.full_pr_workflow()
        for merges in (False, True):
            result = self.scan(merges, workspace=workspace, RCI_REVISIONS=revisions)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(set((self.tmp / 'scanned').read_text().splitlines()),
                         set(self.git('rev-list', *self.selected().split()).splitlines()))

    def test_full_pr_workflow_default_history_finding_fails(self) -> None:
        self.finding('trunk')
        workspace, revisions = self.full_pr_workflow()
        result = self.scan(workspace=workspace, RCI_REVISIONS=revisions)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('found potential secrets', result.stdout)

    def test_full_pr_workflow_own_commit_finding_fails(self) -> None:
        self.finding('pr')
        workspace, revisions = self.full_pr_workflow()
        result = self.scan(workspace=workspace, RCI_REVISIONS=revisions)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('found potential secrets', result.stdout)
