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

Keep any later result tied to its exact source SHA, interpreter, dependency
versions and finite generation settings. Authored properties and a passing
bounded run are different evidence; neither proves absence of vulnerabilities.
