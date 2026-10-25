# Offline interface fuzz/property tests

## Status and scope

These tests were authored for the interfaces in the
[attack-surface map](security.md). They have **not been executed or collected**
as part of this change. No application run, live probing, bug-finding campaign,
coverage measurement or successful-test claim accompanies their addition.

The tests use the existing development dependency Hypothesis and ordinary
Pytest/unittest discovery. No new runtime dependency or application behavior is
introduced. The source target remains the Python 3.14/Linux deployment described
by the repository, not the author's tool environment.

## Interface coverage

| Test module | Generated inputs and contracts |
| --- | --- |
| [CLI](../../tests/test_fuzz_cli.py) | Command/argument combinations, unsupported flags, privilege admission and exact delegation to inert handlers. |
| [Peer inputs](../../tests/test_fuzz_peer_inputs.py) | Typed URI options, option-order invariance, explicit WebSocket admission, duplicate pins, control characters and the IPv4-literal boundary. |
| [Broker](../../tests/test_fuzz_broker.py) | Role/method matrix, key arguments, timeout validation, opaque reply encoding, bounded error output and parent-selected metrics authority. |
| [Acquisition](../../tests/test_fuzz_acquisition.py) | Fixed-source fetch admission with a stubbed runner, small ZIP catalogue projection, remote envelopes/key lists and explicit unknown status. |
| [Archives](../../tests/test_fuzz_archives.py) | Small generated TAR round trips, required inventory, hashes, member types and refusal of restore apply before any archive access. |
| [State I/O](../../tests/test_fuzz_state_io.py) | Byte-limited reads, repeated atomic publication and refusal to replace a symlink leaf inside a temporary directory. |
| [Output](../../tests/test_fuzz_outputs.py) | Alert identity/envelope/privacy contracts and script-safe JSON/markup in the offline HTML viewer. |
| [Sender](../../tests/test_fuzz_sender.py) | Event schema, UTF-8 byte limits, existing receipt reuse and refusal to retry ambiguous or conflicting attempts. |

Each property uses bounded strategies, deterministic generation and
`database=None`; no persistent Hypothesis example database is requested.
Profiles use at most 60, 80 or 100 generated examples per property, depending
on the module. The setting is a generation budget, not a whole-process CPU/RSS
limit. Synthetic hostnames use `.invalid`; IPv4 examples use documentation
space. Synthetic public-key bytes are generated locally.

[OfflineFuzzCase](../../tests/fuzz_support.py) suppresses host syslog and raises
on process or socket creation during each test. Command handlers, runners,
broker contexts and sender/profile operations are mocked as appropriate.
Archives are generated in memory without extraction. Only the state-I/O tests
create ordinary files and a symlink, under their own temporary directory.
HTML is parsed as data; no browser or JavaScript engine is started.

The guards enforce fixture intent during test methods. They are not an OS
sandbox, do not cover module import or third-party plugin behavior and do not
qualify deployment isolation. The tests do not exercise real socket admission,
systemd/cgroup enforcement, privileged permissions/ACLs, GPG, a node, a SimpleX
database, actual forwarding or live recovery.

## Optional later execution

The following command is documentation only; it was not run for this change.
Use the existing approved QA environment and disposable offline Linux sandbox
described in [verification](../VERIFICATION.md#reproducing-source-checks).
Run from the repository root:

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -B -m pytest -q -p no:cacheprovider \
  tests/test_fuzz_cli.py tests/test_fuzz_peer_inputs.py \
  tests/test_fuzz_broker.py tests/test_fuzz_acquisition.py \
  tests/test_fuzz_archives.py tests/test_fuzz_state_io.py \
  tests/test_fuzz_outputs.py tests/test_fuzz_sender.py
```

## Docker runner

The repository [Dockerfile](../../Dockerfile) packages Python 3.14, the existing
development requirements and test sources. The default command selects the eight
fuzz modules above. It runs as an unprivileged user, disables plugin autoload and
bytecode/Pytest caches, and keeps Hypothesis storage under `/tmp`.
The [build-context allowlist](../../.dockerignore) excludes repository history,
local environments and unrelated files. No host source or service mount is needed.

The image was not built or run as part of this change. Build it from the repository
root; the build requires access to the Python image registry and package index:

```sh
docker build -t yggctl-tests .
```

Run the default fuzz properties with the installed dependencies and no network:

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777 yggctl-tests
```

Arguments after the image replace the default Pytest options and module list.
For example, run one module by appending
`-q -p no:cacheprovider tests/test_fuzz_broker.py` to that command.
To select all tests discovered by the repository's Pytest configuration:

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777 \
  yggctl-tests -q -p no:cacheprovider
```

The full suite additionally uses local child processes, Unix sockets and Linux
`/proc` fixtures inside the container. It does not provision a live node.
An explicit `/usr/bin/python3` alias supports existing child-process fixtures.
The base image tag and direct development pins do not constitute an immutable
image digest or a complete transitive dependency lock.

## GitHub Actions

The existing [Source quality and regressions workflow](../../.github/workflows/ci.yml)
has a manual Docker job on `sec/fuzzing`. It builds this Dockerfile on an
Ubuntu 24.04 GitHub-hosted runner, then runs the selected suite without network,
with a read-only filesystem and temporary storage in `/tmp`. The job has a
20-minute timeout and container CPU/memory/process limits. It uses read-only
repository permissions and does not publish the image or deploy anything.

In the fork, open **Actions → Source quality and regressions → Run workflow**:

1. Select branch **sec/fuzzing**. The unchanged `main` version uses the original
   source-quality workflow, not this Docker configuration.
2. Select **fuzz** for the eight new modules (default), or **all** for complete
   Pytest discovery, if the UI displays the suite input.
3. Click **Run workflow** to start the build and tests.

This uses the existing workflow file because it is already registered on the
default branch. If the branch-selection UI shows only the default branch's old
input form, the selected `sec/fuzzing` revision falls back to `fuzz`. With an
authenticated GitHub CLI, the explicit equivalent is:

```sh
gh workflow run ci.yml --repo LuciyVI/yggctl --ref sec/fuzzing -f suite=fuzz
```

Use `-f suite=all` to select the complete suite. These are instructions for a
later operator-triggered run; no workflow was dispatched for this change.
Pushing `sec/fuzzing` alone does not start the Docker job. The existing
non-manual source-quality job continues to run on pushes to `main` and pull
requests; manual dispatch on the modified branch selects only the Docker job.

Keep any later result tied to its exact source SHA, interpreter, dependency
versions and finite generation settings. Authored properties and a passing
bounded run are different evidence; neither proves absence of vulnerabilities.
