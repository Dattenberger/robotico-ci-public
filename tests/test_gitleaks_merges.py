"""Ported from robotico-ci/tests/test_gitleaks_merges.py: preserve the pinned setup and scan behaviours.
Fake tools keep the suite offline; dev-hooks tests the byte-copied merge scanner against real repositories.
@see contract/gitleaks-merges/README.md, tests/test_workflows.py
"""

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from tests import yamlsafe


def load(path: Path) -> dict:
    return yamlsafe.load(path.read_text(encoding="utf-8"))


def step_named(steps: list, name: str) -> dict:
    (step,) = [step for step in steps if step.get("name") == name]
    return step


ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "contract" / "gitleaks-merges"
PIN = CONTRACT / "gitleaks.pin"
PIN_VALUES = dict(line.split("=", 1) for line in PIN.read_text().splitlines() if line and not line.startswith("#"))
IMAGE = PIN_VALUES["image"]
VERSION = PIN_VALUES["version"]


class RunUnderGitHubBash(unittest.TestCase):
    """The run texts executed as GitHub runs them (`bash --noprofile --norc -e -o pipefail`), with docker and the
    merge scan faked: a shallow checkout and every non-zero exit end as an annotated failure, never as clean."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rci-gitleaks-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        shutil.copyfile(ROOT / "tests/fakebin/docker", bin_dir / "docker")
        script = self.tmp / "contract" / "gitleaks-merges" / "gitleaks-merges.sh"
        script.parent.mkdir(parents=True)
        script.write_text('#!/bin/bash\nprintf \'%s\\n\' "$@" > "$FAKE_SCAN_ARGS"\nexit "${FAKE_SCAN_RC:-0}"\n')
        shutil.copyfile(ROOT / "tests/fakebin/gitleaks", bin_dir / "gitleaks")
        for fake in (bin_dir / "docker", bin_dir / "gitleaks", script):
            fake.chmod(0o755)
        (self.tmp / "actions" / "gitleaks-merges").mkdir(parents=True)
        shutil.copyfile(ROOT / "actions/gitleaks-merges/run.sh", self.tmp / "actions/gitleaks-merges/run.sh")
        self.full = self.tmp / "full"
        git = ["git", "--no-optional-locks", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "core.hooksPath=/dev/null", "-C", str(self.full)]
        subprocess.run(["git", "--no-optional-locks", "init", "-q", "-b", "main", str(self.full)], check=True)
        for n in ("1", "2"):
            subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", n], check=True)
        self.shallow = self.tmp / "shallow"
        subprocess.run(["git", "--no-optional-locks", "clone", "-q", "--depth", "1", f"file://{self.full}", str(self.shallow)], check=True)

    def run_text(self, text: str, workspace: Path, **env: str) -> subprocess.CompletedProcess:
        base = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        base.update(PATH=f"{self.tmp / 'bin'}:{os.environ['PATH']}", GITHUB_WORKSPACE=str(workspace),
                    GITHUB_ACTION_PATH=str(self.tmp / "actions" / "gitleaks-merges"), RCI_IMAGE=IMAGE, RCI_BINARY="", RCI_RANGE="", RCI_CONFIG="",
                    FAKE_SCAN_ARGS=str(self.tmp / "scan-args"), FAKE_DOCKER_ARGS=str(self.tmp / "docker-args"),
                    FAKE_GITLEAKS_ARGS=str(self.tmp / "gitleaks-args"),
                    GIT_OPTIONAL_LOCKS="0")
        base.update(env)
        return subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", text], cwd=workspace,
                              env=base, capture_output=True, text=True)

    def composite(self) -> str:
        return 'bash "$GITHUB_ACTION_PATH/run.sh" "$RCI_RANGE"'

    def full_history(self) -> str:
        return step_named(load(ROOT / "actions/gitleaks-scan/action.yml")["runs"]["steps"], "gitleaks (history)")["run"]

    def scans(self) -> tuple:
        return (("image", self.composite(), {}),
                ("binary", self.composite(), {"RCI_IMAGE": "", "RCI_BINARY": "/fake gitleaks"}),
                ("full history", self.full_history(), {"RCI_BINARY": str(self.tmp / "bin" / "gitleaks")}))

    def test_exactly_one_runner_is_required_before_any_scan_or_pull(self) -> None:
        for image, binary in (("", ""), (IMAGE, "/fake gitleaks")):
            with self.subTest(image=image, binary=binary):
                r = self.run_text(self.composite(), self.full, RCI_IMAGE=image, RCI_BINARY=binary)
                self.assertEqual(r.returncode, 1)
                self.assertIn("::error::exactly one", r.stdout)
                self.assertFalse((self.tmp / "scan-args").exists())
                self.assertFalse((self.tmp / "docker-args").exists())

    def test_binary_mode_passes_a_literal_path_and_never_calls_docker(self) -> None:
        binary = '/tools/a gitleaks;$(touch injected)'
        r = self.run_text(self.composite(), self.full, RCI_IMAGE="", RCI_BINARY=binary)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.tmp / "scan-args").read_text().splitlines(),
                         ["--binary", binary, "--repo", str(self.full), "--", "--all"])
        self.assertFalse((self.tmp / "docker-args").exists())
        self.assertFalse((self.full / "injected").exists())

    def test_image_mode_pulls_then_passes_the_image(self) -> None:
        r = self.run_text(self.composite(), self.full)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.tmp / "docker-args").read_text().splitlines(), ["pull", "-q", IMAGE])
        self.assertEqual((self.tmp / "scan-args").read_text().splitlines(),
                         ["--image", IMAGE, "--repo", str(self.full), "--", "--all"])

    def test_a_failed_image_pull_is_an_infrastructure_failure_without_a_scan(self) -> None:
        r = self.run_text(self.composite(), self.full, FAKE_PULL_RC="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("::error::scanner image not loadable", r.stdout)
        self.assertFalse((self.tmp / "scan-args").exists())

    def test_the_composite_annotates_a_finding_and_a_missing_verdict(self) -> None:
        for mode, run, env in self.scans()[:2]:
            for rc, text in (("1", "found potential secrets"), ("2", "no verdict (exit 2)"),
                             ("127", "no verdict (exit 127)")):
                with self.subTest(mode=mode, rc=rc):
                    r = self.run_text(run, self.full, FAKE_SCAN_RC=rc, **env)
                    self.assertEqual(r.returncode, 1)
                    self.assertIn("::error::", r.stdout)
                    self.assertIn(text, r.stdout)
            self.assertEqual(self.run_text(run, self.full, **env).returncode, 0)

    def test_a_shallow_checkout_is_no_verdict_for_both_scans(self) -> None:
        for name, text, env in self.scans():
            with self.subTest(name):
                r = self.run_text(text, self.shallow, **env)
                self.assertEqual(r.returncode, 1)
                self.assertIn("::error::", r.stdout)
                self.assertIn("shallow", r.stdout)
        self.assertEqual(self.run_text(self.full_history(), self.full, RCI_BINARY=str(self.tmp / "bin" / "gitleaks")).returncode, 0)

    def test_the_full_history_scan_annotates_findings_errors_and_an_empty_scan(self) -> None:
        binary = str(self.tmp / "bin" / "gitleaks")
        for env, text in (({"FAKE_GITLEAKS_RC": "99"}, "found potential secrets"),
                          ({"FAKE_GITLEAKS_RC": "2"}, "did not complete (exit 2)"),
                          ({"FAKE_SCANNED": "0"}, "scanned 0 commits")):
            with self.subTest(env=env):
                r = self.run_text(self.full_history(), self.full, RCI_BINARY=binary, **env)
                self.assertEqual(r.returncode, 1)
                self.assertIn("::error::", r.stdout)
                self.assertIn(text, r.stdout)
        r = self.run_text(self.full_history(), self.full, RCI_BINARY=binary)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        args = (self.tmp / "gitleaks-args").read_text().splitlines()
        self.assertEqual(args[0], "detect")
        self.assertIn(f"--config={self.tmp}/actions/gitleaks-merges/../../.gitleaks.toml", args)
        self.assertFalse((self.tmp / "docker-args").exists())

    def test_a_graft_that_hides_history_is_no_verdict_for_both_scans(self) -> None:
        head = subprocess.run(["git", "--no-optional-locks", "-C", str(self.full), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout
        (self.full / ".git" / "info").mkdir(exist_ok=True)
        (self.full / ".git" / "info" / "grafts").write_text(head)
        for name, text, env in self.scans():
            with self.subTest(name):
                r = self.run_text(text, self.full, **env)
                self.assertEqual(r.returncode, 1)
                self.assertIn("::error::", r.stdout)
                self.assertIn("grafts", r.stdout)

    def test_a_symlink_in_the_git_dir_is_refused_before_the_container_resolves_it(self) -> None:
        # It points into the container's /repo mount, so on the host it dangles and every host check reads it as absent.
        (self.full / ".git" / "info").mkdir(exist_ok=True)
        for link in ("info/grafts", "shallow"):
            (self.full / ".git" / link).symlink_to(f"/repo/{link}")
            for name, text, env in self.scans():
                with self.subTest(link=link, scan=name):
                    r = self.run_text(text, self.full, **env)
                    self.assertEqual(r.returncode, 1)
                    self.assertIn("symlink", r.stdout)
            (self.full / ".git" / link).unlink()

    def test_empty_range_keeps_the_exact_full_history_log_options(self) -> None:
        r = self.run_text(self.full_history(), self.full, RCI_BINARY=str(self.tmp / "bin/gitleaks"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("--log-opts=--root --full-history --all --no-textconv --no-ext-diff",
                      (self.tmp / "gitleaks-args").read_text().splitlines())

    def git_revision(self, rev: str) -> str:
        return subprocess.run(["git", "--no-optional-locks", "-C", str(self.full), "rev-parse", rev],
                              capture_output=True, text=True, check=True).stdout.strip()

    def test_standalone_merge_action_ignores_an_ambient_range(self) -> None:
        r = self.run_text('bash "$GITHUB_ACTION_PATH/run.sh"', self.full, RCI_RANGE="--invalid")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.tmp / "scan-args").read_text().splitlines()[-2:], ["--", "--all"])

    def test_valid_range_is_passed_to_both_scans_without_all(self) -> None:
        selected = f"{self.git_revision('HEAD^')}..{self.git_revision('HEAD')}"
        for name, run, env in self.scans():
            with self.subTest(name=name):
                r = self.run_text(run, self.full, RCI_RANGE=selected, **env)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                if name == "full history":
                    args = (self.tmp / "gitleaks-args").read_text().splitlines()
                    self.assertIn(f"--log-opts=--root --full-history --no-textconv --no-ext-diff {selected}", args)
                    self.assertFalse(any("--all" in arg for arg in args))
                else:
                    args = (self.tmp / "scan-args").read_text().splitlines()
                    self.assertEqual(args[-2:], ["--", selected])
                    self.assertNotIn("--all", args)

    def test_invalid_range_is_refused_before_either_scan_or_pull(self) -> None:
        a, b = "a" * 40, "b" * 40
        for selected in ("--all", "main..HEAD", f"{a}...{b}", f"{a.upper()}..{b}",
                         f"{a[:-1]}..{b}", f" {a}..{b}", f"{a}..{b}\n", f"{a}..{b};touch injected",
                         "$(touch injected)"):
            for name, run, env in self.scans():
                with self.subTest(range=selected, scan=name):
                    r = self.run_text(run, self.full, RCI_RANGE=selected, **env)
                    self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                    self.assertIn("::error::invalid range", r.stdout)
                    for name in ("gitleaks-args", "scan-args", "docker-args"):
                        self.assertFalse((self.tmp / name).exists())
                    self.assertFalse((self.full / "injected").exists())

    def test_zero_commits_is_allowed_only_for_an_empty_selection(self) -> None:
        binary = str(self.tmp / "bin/gitleaks")
        head = self.git_revision('HEAD')
        for selected, succeeds in ((f"{head}..{head}", True),
                                   (f"{self.git_revision('HEAD^')}..{head}", False), ("", False)):
            with self.subTest(range=selected):
                r = self.run_text(self.full_history(), self.full, RCI_BINARY=binary, RCI_RANGE=selected,
                                  FAKE_SCANNED="0")
                self.assertEqual(r.returncode, 0 if succeeds else 1, r.stdout + r.stderr)
                if not succeeds:
                    self.assertIn("scanned 0 commits", r.stdout)
        empty = self.tmp / "empty"
        subprocess.run(["git", "--no-optional-locks", "init", "-q", str(empty)], check=True)
        r = self.run_text(self.full_history(), empty, RCI_BINARY=binary, FAKE_SCANNED="0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_unreadable_revision_range_fails_before_history_scan(self) -> None:
        r = self.run_text(self.full_history(), self.full, RCI_BINARY=str(self.tmp / "bin/gitleaks"),
                          RCI_RANGE=f"{'0' * 40}..{'1' * 40}")
        self.assertEqual(r.returncode, 1)
        self.assertIn("git could not count", r.stdout)
        self.assertFalse((self.tmp / "gitleaks-args").exists())

    def test_git_errors_and_missing_counts_are_never_clean(self) -> None:
        binary = str(self.tmp / "bin/gitleaks")
        for error in ("[git] fatal: missing object", "stderr is not empty"):
            for rc in ("0", "99", "2"):
                with self.subTest(error=error, rc=rc):
                    r = self.run_text(self.full_history(), self.full, RCI_BINARY=binary,
                                      FAKE_GIT_ERROR=error, FAKE_GITLEAKS_RC=rc)
                    self.assertEqual(r.returncode, 1)
                    self.assertIn("partial scan, no verdict", r.stdout)
        r = self.run_text(self.full_history(), self.full, RCI_BINARY=binary, FAKE_NO_COUNT="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("scanned no commits", r.stdout)

    def test_explicit_config_is_one_literal_argument(self) -> None:
        config = 'a config;$(touch injected)'
        r = self.run_text(self.full_history(), self.full, RCI_BINARY=str(self.tmp / "bin/gitleaks"),
                          RCI_CONFIG=config)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"--config={config}", (self.tmp / "gitleaks-args").read_text().splitlines())
        self.assertFalse((self.full / "injected").exists())

    def test_scanner_environment_ignores_global_config_and_replace_refs(self) -> None:
        output = self.tmp / "env"
        r = self.run_text(self.full_history(), self.full, RCI_BINARY=str(self.tmp / "bin/gitleaks"),
                          FAKE_ENV_OUTPUT=str(output), GITLEAKS_CONFIG="untrusted", GITLEAKS_CONFIG_TOML="untrusted")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        env = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertNotIn("GITLEAKS_CONFIG", env)
        self.assertNotIn("GITLEAKS_CONFIG_TOML", env)
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_non_repository_is_no_verdict_for_all_scan_modes(self) -> None:
        workspace = self.tmp / "not-a-repository"
        workspace.mkdir()
        for name, run, env in self.scans():
            with self.subTest(scan=name):
                r = self.run_text(run, workspace, **env)
                self.assertEqual(r.returncode, 1)
                self.assertIn("::error::", r.stdout)
        self.assertFalse((self.tmp / "gitleaks-args").exists())
        self.assertFalse((self.tmp / "scan-args").exists())


class PinnedBinary(unittest.TestCase):
    """Run the installer with a private pin and release tarball, never a real network request."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rci-gitleaks-pinned-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.action_path = self.tmp / "actions" / "gitleaks-pinned"
        self.action_path.mkdir(parents=True)
        shutil.copyfile(ROOT / "actions/gitleaks-pinned/install.sh", self.action_path / "install.sh")
        self.pin = self.tmp / "contract" / "gitleaks-merges" / "gitleaks.pin"
        self.pin.parent.mkdir(parents=True)
        self.pin.write_bytes(PIN.read_bytes())
        self.runner_temp = self.tmp / "runner temp"
        self.runner_temp.mkdir()
        self.output = self.tmp / "output"
        self.github_path = self.tmp / "path"
        self.curl_args = self.tmp / "curl-args"
        self.archive = self.tmp / "release.tar.gz"
        self.fake("gitleaks", 'echo "${FAKE_PATH_VERSION:-other}"\nexit "${FAKE_PATH_RC:-0}"\n')
        shutil.copyfile(ROOT / "tests/fakebin/curl", self.bin / "curl")
        (self.bin / "curl").chmod(0o755)

    def fake(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + body)
        path.chmod(0o755)

    def release(self, version: str = VERSION, *, member: str = "gitleaks", executable: bool = True) -> None:
        body = f'#!/bin/bash\necho "{version}"\n'.encode()
        with tarfile.open(self.archive, "w:gz") as archive:
            entry = tarfile.TarInfo(member)
            entry.size = len(body)
            entry.mode = 0o755 if executable else 0o644
            archive.addfile(entry, io.BytesIO(body))
            extra = tarfile.TarInfo("unwanted")
            archive.addfile(extra, io.BytesIO())
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.pin.write_text(PIN.read_text().replace(PIN_VALUES["linux_x64_sha256"], digest))

    def run_action(self, **env: str) -> subprocess.CompletedProcess:
        self.output.write_text("")
        self.github_path.write_text("")
        self.curl_args.write_text("")
        base = dict(os.environ)
        base.update(PATH=f"{self.bin}:{os.environ['PATH']}", RUNNER_OS="Linux", RUNNER_ARCH="X64",
                    RUNNER_TEMP=str(self.runner_temp), GITHUB_ACTION_PATH=str(self.action_path),
                    GITHUB_OUTPUT=str(self.output), GITHUB_PATH=str(self.github_path),
                    FAKE_CURL_ARGS=str(self.curl_args), FAKE_ARCHIVE=str(self.archive))
        base.update(env)
        return subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(self.action_path / "install.sh")],
                              cwd=self.tmp, env=base, capture_output=True, text=True)

    def assert_infrastructure_failure(self, result: subprocess.CompletedProcess) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error::", result.stdout)
        self.assertIn("infrastructure, no scan", result.stdout)
        self.assertEqual(self.output.read_text(), "")
        self.assertEqual(self.github_path.read_text(), "")

    def test_the_pinned_path_binary_is_reused_without_a_download(self) -> None:
        for version in (VERSION, f"v{VERSION}"):
            with self.subTest(version=version):
                r = self.run_action(FAKE_PATH_VERSION=version, FAKE_CURL_RC="99")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(self.output.read_text(), f"path={self.bin / 'gitleaks'}\n")
                self.assertEqual(self.curl_args.read_text(), "")
                self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_another_or_failed_path_version_downloads_and_verifies_the_release(self) -> None:
        self.release(f"v{VERSION}")
        for version, rc in (("other", "0"), (VERSION, "1"), (f"vv{VERSION}", "0"), (f"{VERSION} extra", "0")):
            with self.subTest(version=version, rc=rc):
                r = self.run_action(FAKE_PATH_VERSION=version, FAKE_PATH_RC=rc)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                install = self.runner_temp / f"gitleaks-{VERSION}"
                self.assertEqual(self.output.read_text(), f"path={install / 'gitleaks'}\n")
                self.assertEqual(self.github_path.read_text(), f"{install}\n")
                self.assertEqual([p.name for p in install.iterdir()], ["gitleaks"])
                args = self.curl_args.read_text().splitlines()
                self.assertEqual(args[:6], ["-fsSL", "--proto", "=https", "--retry", "3", "-o"])
                self.assertEqual(args[-1], "https://github.com/gitleaks/gitleaks/releases/download/"
                                 f"v{VERSION}/gitleaks_{VERSION}_linux_x64.tar.gz")
                self.assertEqual(list(self.runner_temp.iterdir()), [install])

    def test_a_missing_path_binary_downloads_the_release(self) -> None:
        (self.bin / "gitleaks").unlink()
        # Only these tools are visible, so a scanner installed on the host cannot satisfy command -v.
        for name in ("bash", "dirname", "cp", "mktemp", "sha256sum", "mkdir", "tar", "gzip", "rm"):
            (self.bin / name).symlink_to(shutil.which(name))
        self.release()
        r = self.run_action(PATH=str(self.bin))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(self.curl_args.read_text())

    def test_a_sha_mismatch_fails_before_extraction(self) -> None:
        self.release()
        self.pin.write_text(PIN.read_text().replace(PIN_VALUES["linux_x64_sha256"], "0" * 64))
        self.assert_infrastructure_failure(self.run_action())
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_a_bad_or_missing_pin_fails_without_downloading(self) -> None:
        valid = PIN.read_text()
        cases = ["", valid + "extra=value\n", valid + f"version={VERSION}\n", valid + f"image={IMAGE}\n",
                 valid + f"linux_x64_sha256={PIN_VALUES['linux_x64_sha256']}\n",
                 valid.replace(f"version={VERSION}\n", ""), valid.replace(f"image={IMAGE}\n", ""),
                 valid.replace(f"linux_x64_sha256={PIN_VALUES['linux_x64_sha256']}\n", ""),
                 valid.replace(VERSION, f"v{VERSION}"), valid.replace(IMAGE, "unpinned:latest"),
                 valid.replace(PIN_VALUES["linux_x64_sha256"], "A" * 64),
                 valid.replace(VERSION, "$(touch injected)"), valid.replace("version=", "version ="),
                 valid.replace("\n", "\r\n")]
        for pin in cases:
            with self.subTest(pin=pin):
                self.pin.write_text(pin)
                self.assert_infrastructure_failure(self.run_action(FAKE_PATH_VERSION=VERSION))
                self.assertEqual(self.curl_args.read_text(), "")
                self.assertFalse((self.tmp / "injected").exists())
        self.pin.unlink()
        self.assert_infrastructure_failure(self.run_action())
        self.assertEqual(self.curl_args.read_text(), "")

    def test_a_pin_without_a_final_newline_and_with_comments_is_valid(self) -> None:
        self.pin.write_text("\n# comment\n" + PIN.read_text().rstrip("\n"))
        r = self.run_action(FAKE_PATH_VERSION=VERSION)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_other_runner_platforms_fail_without_downloading(self) -> None:
        for os_name, arch in (("Windows", "X64"), ("Linux", "ARM64"), ("", "")):
            with self.subTest(os=os_name, arch=arch):
                r = self.run_action(RUNNER_OS=os_name, RUNNER_ARCH=arch)
                self.assert_infrastructure_failure(r)
                self.assertIn("Linux x64 only", r.stdout)
                self.assertEqual(self.curl_args.read_text(), "")

    def test_download_and_extraction_failures_are_infrastructure_errors(self) -> None:
        self.assert_infrastructure_failure(self.run_action(FAKE_CURL_RC="22"))
        self.archive.write_bytes(b"not a tarball")
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.pin.write_text(PIN.read_text().replace(PIN_VALUES["linux_x64_sha256"], digest))
        self.assert_infrastructure_failure(self.run_action())

    def test_a_release_without_an_executable_of_the_pinned_version_fails(self) -> None:
        for version, member, executable in (("wrong", "gitleaks", True), (VERSION, "other", True),
                                            (VERSION, "gitleaks", False)):
            with self.subTest(version=version, member=member, executable=executable):
                self.release(version, member=member, executable=executable)
                self.assert_infrastructure_failure(self.run_action())


if __name__ == "__main__":
    unittest.main()
