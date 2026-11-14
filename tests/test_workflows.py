"""Public workflow and action contracts, ported from robotico-ci/tests/test_gitleaks_merges.py.

Workflow and action YAML uses the same safe loader as the source repository; shell tests run offline.
@see README.md, tests/test_gitleaks_merges.py
"""

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests import yamlsafe
from tests.test_gitleaks_merges import ROOT, load, step_named

CONTRACT = ROOT / 'contract/gitleaks-merges'
CHECKOUT = 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262'
RUNNER = "${{ vars.CI_RUNS_ON_S || 'ubuntu-latest' }}"


class Copy(unittest.TestCase):
    def test_the_copy_matches_its_source_json(self) -> None:
        source = json.loads((CONTRACT / 'SOURCE.json').read_text())
        self.assertEqual(source['repo'], 'Dattenberger/robotico-packages')
        self.assertEqual(source['path'], 'packages/dev-hooks/checks/gitleaks-merges.sh')
        self.assertRegex(source['commit'], r'^[0-9a-f]{40}$')
        self.assertEqual(source['tag'], 'pending')
        self.assertEqual(list(source['files']), ['gitleaks-merges.sh', 'gitleaks.pin'])
        for name, digest in source['files'].items():
            self.assertEqual(digest, hashlib.sha256((CONTRACT / name).read_bytes()).hexdigest())

    def test_the_pin_has_the_three_strict_values(self) -> None:
        values = dict(line.split('=', 1) for line in (CONTRACT / 'gitleaks.pin').read_text().splitlines()
                      if line and not line.startswith('#'))
        self.assertEqual(set(values), {'version', 'image', 'linux_x64_sha256'})
        self.assertRegex(values['version'], r'^[0-9]+\.[0-9]+\.[0-9]+$')
        self.assertRegex(values['image'], r'^[a-z0-9./-]+@sha256:[0-9a-f]{64}$')
        self.assertRegex(values['linux_x64_sha256'], r'^[0-9a-f]{64}$')

    def test_the_copy_and_shared_scripts_have_the_right_modes(self) -> None:
        for name, mode in (('contract/gitleaks-merges/gitleaks-merges.sh', 0o755),
                           ('contract/gitleaks-merges/gitleaks.pin', 0o644),
                           ('actions/gitleaks-pinned/install.sh', 0o755),
                           ('actions/gitleaks-merges/run.sh', 0o755)):
            path = ROOT / name
            self.assertEqual(bool(path.stat().st_mode & stat.S_IXUSR), mode == 0o755)
            entry = subprocess.run(['git', '--no-optional-locks', '-C', str(ROOT), 'ls-files', '-s', '--', name],
                                   capture_output=True, text=True, check=True).stdout
            # New files have no index entry until the orchestrator stages them. Check it whenever present.
            if entry:
                self.assertTrue(entry.startswith(f'100{mode:o} '), entry)

    def test_only_the_shared_merge_runner_calls_the_contract(self) -> None:
        callers = [path.relative_to(ROOT).as_posix() for folder in ('.github', 'actions')
                   for path in (ROOT / folder).rglob('*')
                   if path.is_file() and 'gitleaks-merges.sh' in path.read_text()]
        self.assertEqual(callers, ['actions/gitleaks-merges/run.sh'])


class Composites(unittest.TestCase):
    def test_standalone_merges_preserves_its_interface_and_uses_env_only(self) -> None:
        action = load(ROOT / 'actions/gitleaks-merges/action.yml')
        self.assertEqual(set(action['inputs']), {'image', 'binary', 'revisions'})
        for name in ('image', 'binary', 'revisions'):
            self.assertEqual(action['inputs'][name]['required'], False)
            self.assertEqual(action['inputs'][name]['default'], '')
        self.assertEqual(action['runs']['using'], 'composite')
        (step,) = action['runs']['steps']
        self.assertEqual(step['env'], {'RCI_IMAGE': '${{ inputs.image }}', 'RCI_BINARY': '${{ inputs.binary }}',
                                       'RCI_REVISIONS': '${{ inputs.revisions }}'})
        self.assertEqual(step['shell'], 'bash')
        self.assertEqual(step['run'], 'bash "$GITHUB_ACTION_PATH/run.sh" "" "$RCI_REVISIONS"')
        script = (ROOT / 'actions/gitleaks-merges/run.sh').read_text()
        self.assertNotIn('${{', script)
        self.assertIn('docker pull -q "$RCI_IMAGE"', script)
        self.assertRegex(script, r'\n  0\) ;;\n')
        self.assertRegex(script, r'\n  \*\).*exit 1 ;;\n')

    def test_pinned_has_no_inputs_and_exposes_the_shared_installer_output(self) -> None:
        action = load(ROOT / 'actions/gitleaks-pinned/action.yml')
        self.assertNotIn('inputs', action)
        self.assertEqual(action['outputs']['path']['value'], '${{ steps.install.outputs.path }}')
        self.assertEqual(action['runs']['using'], 'composite')
        (step,) = action['runs']['steps']
        self.assertEqual(step['id'], 'install')
        self.assertEqual(step['shell'], 'bash')
        self.assertEqual(step['run'], 'bash "$GITHUB_ACTION_PATH/install.sh"')
        script = (ROOT / 'actions/gitleaks-pinned/install.sh').read_text()
        self.assertIn('${BASH_SOURCE[0]}', script)
        self.assertNotIn('GITHUB_ACTION_PATH', script)

    def test_scan_inputs_steps_and_shared_scripts(self) -> None:
        action = load(ROOT / 'actions/gitleaks-scan/action.yml')
        self.assertEqual(set(action['inputs']), {'range', 'config', 'revisions'})
        for name in ('range', 'config', 'revisions'):
            self.assertEqual(action['inputs'][name]['required'], False)
            self.assertEqual(action['inputs'][name]['default'], '')
        self.assertEqual(action['runs']['using'], 'composite')
        install, history, merges = action['runs']['steps']
        self.assertEqual(install, {'name': 'Locate or install pinned gitleaks', 'id': 'gitleaks', 'shell': 'bash',
                                  'run': 'bash "$GITHUB_ACTION_PATH/../gitleaks-pinned/install.sh"'})
        self.assertEqual(history['name'], 'gitleaks (history)')
        self.assertEqual(history['shell'], 'bash')
        self.assertEqual(history['env'], {'RCI_BINARY': '${{ steps.gitleaks.outputs.path }}',
                                         'RCI_RANGE': '${{ inputs.range }}', 'RCI_REVISIONS': '${{ inputs.revisions }}',
                                         'RCI_CONFIG': '${{ inputs.config }}'})
        self.assertEqual(merges, {'name': "gitleaks over the merges' own content", 'shell': 'bash',
                                 'env': {'RCI_IMAGE': '', 'RCI_BINARY': '${{ steps.gitleaks.outputs.path }}',
                                         'RCI_RANGE': '${{ inputs.range }}', 'RCI_REVISIONS': '${{ inputs.revisions }}'},
                                 'run': 'bash "$GITHUB_ACTION_PATH/../gitleaks-merges/run.sh" "$RCI_RANGE" "$RCI_REVISIONS"'})
        for step in (install, history, merges):
            self.assertNotIn('uses', step)
            self.assertNotIn('${{', step['run'])
        self.assertIn('GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1', history['run'])
        self.assertIn('--root --full-history --all --no-textconv --no-ext-diff', history['run'])
        self.assertLess(history['run'].index('stderr is not empty'), history['run'].index('case $rc in'))
        self.assertNotIn('docker', json.dumps(action))


class WorkflowShape(unittest.TestCase):
    def test_required_workflow_triggers_permissions_and_runner(self) -> None:
        doc = load(ROOT / '.github/workflows/secret-scan.yml')
        self.assertEqual(set(doc), {'name', 'on', 'permissions', 'jobs'})
        self.assertEqual(doc['name'], 'secret-scan')
        self.assertEqual(doc['on'], {'pull_request': {'types': ['opened', 'synchronize', 'reopened', 'edited']}, 'workflow_call': {'inputs': {
            'history': {'description': 'History to scan: full or pr (pr requires a pull_request event)',
                        'type': 'string', 'default': 'full'}}}})
        self.assertEqual(doc['permissions'], {'contents': 'read'})
        self.assertEqual(set(doc['jobs']), {'gitleaks'})
        job = doc['jobs']['gitleaks']
        self.assertEqual(set(job), {'runs-on', 'steps'})
        self.assertEqual(job['runs-on'], RUNNER)

    def test_fetch_takes_inputs_from_env_and_scan_uses_the_public_remote_action(self) -> None:
        fetch, select, scan = load(ROOT / '.github/workflows/secret-scan.yml')['jobs']['gitleaks']['steps']
        self.assertEqual(fetch['name'], 'Fetch history')
        self.assertEqual(fetch['shell'], 'bash')
        self.assertEqual(fetch['env'], {'RCI_TOKEN': '${{ github.token }}', 'RCI_SERVER': '${{ github.server_url }}',
                                        'RCI_REPO': '${{ github.repository }}', 'RCI_SHA': '${{ github.sha }}',
                                        'RCI_HISTORY': '${{ inputs.history }}', 'RCI_EVENT': '${{ github.event_name }}',
                                        'RCI_HEAD': '${{ github.event.pull_request.head.sha }}',
                                        'RCI_DEFAULT_BRANCH': '${{ github.event.repository.default_branch }}'})
        self.assertNotIn('${{', fetch['run'])
        self.assertEqual(select['id'], 'history')
        self.assertEqual(select['shell'], 'bash')
        self.assertEqual(select['env'], {'RCI_HISTORY': '${{ inputs.history }}',
                                         'RCI_EVENT': '${{ github.event_name }}',
                                         'RCI_BASE': '${{ github.event.pull_request.base.sha }}',
                                         'RCI_HEAD': '${{ github.event.pull_request.head.sha }}'})
        self.assertNotIn('${{', select['run'])
        self.assertEqual(scan, {'uses': 'Dattenberger/robotico-ci-public/actions/gitleaks-scan@v1',
                                'with': {'range': '${{ steps.history.outputs.range }}',
                                         'revisions': '${{ steps.history.outputs.revisions }}'}})

    def test_ci_tests_the_local_tree_with_one_required_job(self) -> None:
        doc = load(ROOT / '.github/workflows/ci.yml')
        self.assertEqual(doc['on'], {'pull_request': None, 'push': {'branches': ['main']}})
        self.assertEqual(doc['permissions'], {'contents': 'read'})
        self.assertEqual(set(doc['jobs']), {'ci'})
        job = doc['jobs']['ci']
        self.assertEqual(set(job), {'runs-on', 'steps'})
        self.assertEqual(job['runs-on'], RUNNER)
        checkout, tests, scan = job['steps']
        self.assertEqual(checkout, {'uses': CHECKOUT, 'with': {'fetch-depth': 0, 'persist-credentials': False}})
        self.assertEqual(tests, {'name': 'Unit tests', 'run': 'python3 -m unittest discover -s tests -t .'})
        self.assertEqual(scan, {'uses': './actions/gitleaks-scan'})


class FetchHistory(unittest.TestCase):
    """The fetch step against a local origin (file URL), offline."""

    def git(self, cwd: Path, *args: str) -> str:
        env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
                   GIT_COMMITTER_EMAIL='t@t', GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
        return subprocess.run(['git', '-C', str(cwd), *args], env=env, check=True, capture_output=True,
                              text=True).stdout.strip()

    def origin(self, tmp: Path) -> tuple:
        """owner/repo with main (a gitlink without .gitmodules), a side branch, a tag and an unreferenced commit."""
        src = tmp / 'src'
        src.mkdir()
        self.git(src, 'init', '-q', '-b', 'main')
        (src / 'a.txt').write_text('a\n')
        self.git(src, 'add', 'a.txt')
        self.git(src, 'commit', '-q', '-m', 'a')
        self.git(src, 'update-index', '--add', '--cacheinfo', f"160000,{'1' * 40},vendored/tool")
        self.git(src, 'commit', '-q', '-m', 'gitlink without .gitmodules')
        self.git(src, 'tag', 'v0')
        self.git(src, 'checkout', '-q', '-b', 'side')
        (src / 'b.txt').write_text('b\n')
        self.git(src, 'add', 'b.txt')
        self.git(src, 'commit', '-q', '-m', 'b')
        self.git(src, 'checkout', '-q', '--detach', 'main')
        (src / 'c.txt').write_text('c\n')
        self.git(src, 'add', 'c.txt')
        self.git(src, 'commit', '-q', '-m', 'merge ref stand-in')
        merge = self.git(src, 'rev-parse', 'HEAD')
        self.git(src, 'checkout', '-q', 'main')
        repo = tmp / 'owner' / 'repo.git'
        repo.parent.mkdir()
        self.git(tmp, 'clone', '-q', '--bare', str(src), str(repo))
        self.git(repo, 'update-ref', 'refs/pull/1/merge', merge)
        self.git(repo, 'config', 'uploadpack.allowAnySHA1InWant', 'true')
        return merge

    def fetch(self, tmp: Path, sha: str, workspace: Path, global_config: str = '/dev/null',
              **extra: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, RCI_TOKEN='t0ken', RCI_SERVER=f'file://{tmp}', RCI_REPO='owner/repo.git',
                   RCI_SHA=sha, RCI_HISTORY='full', RCI_EVENT='push', RCI_BASE='', RCI_HEAD='',
                   RCI_DEFAULT_BRANCH='', GIT_CONFIG_GLOBAL=global_config, GIT_CONFIG_NOSYSTEM='1')
        env.update(extra)
        steps = load(ROOT / '.github/workflows/secret-scan.yml')['jobs']['gitleaks']['steps']
        script = step_named(steps, 'Fetch history')['run']
        return subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
                              cwd=workspace, env=env, capture_output=True, text=True)

    def test_full_history_of_a_repository_with_a_broken_gitlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix='rci-fetch-') as raw:
            tmp = Path(raw)
            merge = self.origin(tmp)
            ws = tmp / 'ws'
            ws.mkdir()
            result = self.fetch(tmp, merge, ws)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.git(ws, 'rev-parse', 'HEAD'), merge)
            self.assertEqual(self.git(ws, 'rev-list', '--count', '--all'), '4')
            self.assertEqual(self.git(ws, 'for-each-ref', '--format=%(refname)').split(),
                             ['refs/remotes/origin/main', 'refs/remotes/origin/side', 'refs/remotes/rci/checkout',
                              'refs/tags/v0'])
            self.assertTrue((ws / 'c.txt').is_file())
            self.assertEqual(self.git(ws, 'status', '--porcelain'), '')
            self.assertNotIn('t0ken', (ws / '.git/config').read_text())
            self.assertIn('::add-mask::', result.stdout)

    def test_full_pr_fetches_only_default_history_and_pr_head(self) -> None:
        with tempfile.TemporaryDirectory(prefix='rci-fetch-') as raw:
            tmp = Path(raw)
            head = self.origin(tmp)
            origin = tmp / 'owner/repo.git'
            default = self.git(origin, 'rev-parse', 'main')
            other = self.git(origin, 'rev-parse', 'side')
            self.git(origin, 'update-ref', 'refs/heads/stable', default)
            # The event commit of a PR run is the synthetic merge of the default tip and the PR head.
            env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
                       GIT_COMMITTER_EMAIL='t@t')
            merge = subprocess.run(['git', '-C', str(origin), 'commit-tree', f'{head}^{{tree}}', '-p', default,
                                    '-p', head, '-m', 'pr merge'], env=env, check=True, capture_output=True,
                                   text=True).stdout.strip()
            self.git(origin, 'update-ref', 'refs/pull/2/merge', merge)
            ws = tmp / 'ws'
            ws.mkdir()
            result = self.fetch(tmp, merge, ws, RCI_HISTORY='full', RCI_EVENT='pull_request',
                                RCI_DEFAULT_BRANCH='stable', RCI_HEAD=head)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # The checkout is the merged tree, so the scan reads the merged .gitleaks.toml and .gitleaksignore.
            self.assertEqual(self.git(ws, 'rev-parse', 'HEAD'), merge)
            self.assertEqual(self.git(ws, 'rev-parse', 'refs/remotes/rci/default'), default)
            self.assertEqual(self.git(ws, 'rev-parse', 'refs/remotes/rci/head'), head)
            self.assertEqual(self.git(ws, 'for-each-ref', '--format=%(refname)').split(),
                             ['refs/remotes/origin/stable', 'refs/remotes/rci/checkout', 'refs/remotes/rci/default',
                              'refs/remotes/rci/head'])
            self.assertNotIn(other, self.git(ws, 'rev-list', '--all').splitlines())
            self.assertEqual(self.git(ws, 'rev-list', '--count', '--all'), '4')
            self.assertNotIn('t0ken', (ws / '.git/config').read_text())

    def test_pr_mode_fetch_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(prefix='rci-fetch-') as raw:
            tmp = Path(raw)
            head = self.origin(tmp)
            for history in ('pr', ''):
                ws = tmp / ('ws-' + history)
                ws.mkdir()
                result = self.fetch(tmp, head, ws, RCI_HISTORY=history, RCI_EVENT='pull_request')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.git(ws, 'rev-list', '--count', '--all'), '4')
                self.assertEqual(self.git(ws, 'rev-parse', 'HEAD'), head)

    def test_full_pr_rejects_invalid_or_missing_scope_before_fetching(self) -> None:
        with tempfile.TemporaryDirectory(prefix='rci-fetch-') as raw:
            tmp = Path(raw)
            head = self.origin(tmp)
            for n, (branch, pr_head) in enumerate((('', head), ('../bad', head), ('bad..name', head),
                                                  ('main', ''), ('main', 'HEAD'), ('main', head + '\n'))):
                ws = tmp / f'ws-{n}'
                ws.mkdir()
                result = self.fetch(tmp, head, ws, RCI_EVENT='pull_request',
                                    RCI_DEFAULT_BRANCH=branch, RCI_HEAD=pr_head)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('::error::', result.stdout)
                self.assertEqual(list(ws.iterdir()), [])

    def test_harmless_runner_http_settings_pass_the_credential_guard(self) -> None:
        with tempfile.TemporaryDirectory(prefix='rci-fetch-') as raw:
            tmp = Path(raw)
            merge = self.origin(tmp)
            config = tmp / 'gitconfig'
            config.write_text('[http]\n\tversion = HTTP/1.1\n\tsslCAInfo = /etc/ssl/certs/ca-certificates.crt\n')
            ws = tmp / 'ws'
            ws.mkdir()
            result = self.fetch(tmp, merge, ws, str(config))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.git(ws, 'rev-parse', 'HEAD'), merge)

    def test_refuses_an_invalid_sha_or_a_used_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix='rci-fetch-') as raw:
            tmp = Path(raw)
            merge = self.origin(tmp)
            for sha in ('', 'HEAD', merge.upper(), '$(touch injected)'):
                with self.subTest(sha=sha):
                    ws = tmp / f'ws-{abs(hash(sha))}'
                    ws.mkdir()
                    result = self.fetch(tmp, sha, ws)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('::error::invalid commit SHA', result.stdout)
                    self.assertEqual(list(ws.iterdir()), [])
            used = tmp / 'used'
            used.mkdir()
            (used / 'leftover').write_text('x')
            result = self.fetch(tmp, merge, used)
            self.assertEqual(result.returncode, 1)
            self.assertIn('::error::the workspace is not empty', result.stdout)


class SelectHistory(unittest.TestCase):
    def select(self, history: str, event: str, base: str = 'a' * 40, head: str = 'b' * 40,
               default: str = '') -> tuple:
        with tempfile.TemporaryDirectory(prefix='rci-select-history-') as tmp:
            if default:
                subprocess.run(['git', 'init', '-q', tmp], check=True)
                # A real, empty-tree commit gives the selection step a resolvable default tip.
                env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t',
                           GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t')
                subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', tmp, 'commit',
                                         '-q', '--allow-empty', '-m', 'fixture'], env=env, check=True)
                tip = subprocess.check_output(['git', '-C', tmp, 'rev-parse', 'HEAD'], text=True).strip()
                subprocess.run(['git', '-C', tmp, 'update-ref', 'refs/remotes/rci/default', tip], check=True)
            output = Path(tmp) / 'output'
            env = dict(os.environ, RCI_HISTORY=history, RCI_EVENT=event, RCI_BASE=base, RCI_HEAD=head,
                       GITHUB_OUTPUT=str(output), GIT_CEILING_DIRECTORIES=str(Path(tmp).parent))
            steps = load(ROOT / '.github/workflows/secret-scan.yml')['jobs']['gitleaks']['steps']
            script = step_named(steps, 'Select history')['run']
            result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
                                    cwd=tmp, env=env, capture_output=True, text=True)
            return result, output.read_text() if output.exists() else ''

    def test_direct_and_called_pr_modes_select_the_pr_shas(self) -> None:
        for history in ('', 'pr'):
            with self.subTest(history=history):
                result, output = self.select(history, 'pull_request')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, f"range={'a' * 40}..{'b' * 40}\n")

    def test_full_history_calls_scan_all_history_on_other_events(self) -> None:
        for event in ('push', 'schedule', 'workflow_dispatch'):
            with self.subTest(event=event):
                result, output = self.select('full', event)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, 'range=\n')

    def test_full_pr_selects_default_tip_and_pr_head(self) -> None:
        result, output = self.select('full', 'pull_request', base='c' * 40, default='present')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(output, rf"^range=\nrevisions=[0-9a-f]{{40}} {'b' * 40}\n$")
        self.assertNotIn('c' * 40, output)

    def test_full_pr_refuses_a_missing_default_tip_or_invalid_head(self) -> None:
        for head, default in (('b' * 40, ''), ('HEAD', 'present'), ('', 'present')):
            result, output = self.select('full', 'pull_request', head=head, default=default)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('::error::', result.stdout)
            self.assertEqual(output, '')

    def test_pr_mode_requires_a_pr_event(self) -> None:
        for history in ('', 'pr'):
            for event in ('push', 'schedule', 'workflow_dispatch'):
                with self.subTest(history=history, event=event):
                    result, output = self.select(history, event)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('::error::history: pr requires a pull_request event', result.stdout)
                    self.assertEqual(output, '')

    def test_invalid_history_or_missing_pr_shas_fails(self) -> None:
        result, output = self.select('invalid', 'pull_request')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output, '')
        for base, head in (('', ''), ('main', 'HEAD'), ('a' * 40, '$(touch injected)'),
                           ('a' * 40, 'B' * 40), ('a' * 40, 'b' * 40 + '\n')):
            with self.subTest(base=base, head=head):
                result, output = self.select('pr', 'pull_request', base, head)
                self.assertEqual(result.returncode, 1)
                self.assertIn('::error::invalid pull request commit SHAs', result.stdout)
                self.assertEqual(output, '')


class YamlsafeTest(unittest.TestCase):
    """Copied with the loader from robotico-ci/tests/test_release_contracts.py."""

    def test_loads_a_mapping_with_string_keys(self) -> None:
        self.assertEqual({"on": "push", "jobs": {"true": 1}}, yamlsafe.load("on: push\njobs:\n  true: 1\n"))

    def test_refuses(self) -> None:
        for label, text in {"duplicate": "a: 1\na: 2\n", "nested duplicate": "a:\n  b: 1\n  b: 2\n", "list root": "- a\n",
                            "empty": "", "scalar": "x", "anchor": "a: &x 1\nb: *x\n", "broken": "a: [\n"}.items():
            with self.subTest(label):
                with self.assertRaises(yamlsafe.YamlError):
                    yamlsafe.load(text)
