"""Repeat one offline property test until coverage inactivity or a time budget.

This runner measures the union of executed source lines and arcs. It does not
interpret failures, probe services, or adapt inputs to an observed failure.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from typing import Callable

from coverage import CoverageData
from coverage.exceptions import CoverageException


ROOT = Path(__file__).resolve().parents[1]
MODULES = frozenset(
    f"tests/test_fuzz_{name}.py"
    for name in (
        "acquisition", "archives", "broker", "cli", "outputs", "peer_inputs", "sender", "state_io"
    )
)
MAX_SECONDS = 5 * 60 * 60
MAX_SEED = 2**64 - 1
OUTPUT_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class CoveragePoints:
    lines: frozenset[tuple[str, int]] = frozenset()
    arcs: frozenset[tuple[str, int, int]] = frozenset()


@dataclass
class CoverageProgress:
    started_at: float
    last_progress_at: float
    lines: set[tuple[str, int]] = field(default_factory=set)
    arcs: set[tuple[str, int, int]] = field(default_factory=set)
    rounds: int = 0

    def observe(self, points: CoveragePoints, now: float) -> tuple[int, int]:
        new_lines = len(points.lines - self.lines)
        new_arcs = len(points.arcs - self.arcs)
        self.lines.update(points.lines)
        self.arcs.update(points.arcs)
        self.rounds += 1
        if new_lines or new_arcs:
            self.last_progress_at = now
        return new_lines, new_arcs

    def stop_reason(self, now: float, plateau_seconds: int, max_seconds: int) -> str | None:
        if now - self.started_at >= max_seconds:
            return "max_seconds"
        if now - self.last_progress_at >= plateau_seconds:
            return "plateau"
        return None

    def remaining(self, now: float, plateau_seconds: int, max_seconds: int) -> float:
        return max(
            0.0,
            min(
                self.started_at + max_seconds - now,
                self.last_progress_at + plateau_seconds - now,
            ),
        )


@dataclass(frozen=True)
class RoundResult:
    returncode: int
    output_bytes: int
    stop_reason: str | None = None


def validate_test_nodeid(value: str, root: Path = ROOT) -> str:
    """Admit an exact method in the authored offline modules without imports."""
    parts = value.split("::")
    if (
        len(parts) != 3
        or parts[0] not in MODULES
        or not parts[1].isidentifier()
        or not parts[2].isidentifier()
        or not parts[2].startswith("test_")
    ):
        raise argparse.ArgumentTypeError("select an exact method in tests/test_fuzz_*.py")
    try:
        tree = ast.parse((root / parts[0]).read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeError):
        raise argparse.ArgumentTypeError("selected test source is unavailable or invalid") from None
    if not any(
        isinstance(node, ast.ClassDef)
        and node.name == parts[1]
        and any(
            isinstance(member, ast.FunctionDef) and member.name == parts[2]
            for member in node.body
        )
        for node in tree.body
    ):
        raise argparse.ArgumentTypeError("selected test method is not defined")
    return value


def bounded_integer(lower: int, upper: int):
    def parse(value: str) -> int:
        try:
            result = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("expected an integer") from None
        if not lower <= result <= upper:
            raise argparse.ArgumentTypeError(f"expected an integer in {lower}..{upper}")
        return result

    return parse


def read_coverage(path: Path, root: Path = ROOT) -> CoveragePoints:
    if not path.is_file():
        raise RuntimeError("coverage data is missing")
    data = CoverageData(basename=str(path))
    data.read()
    if not data.has_arcs():
        raise RuntimeError("branch coverage data is missing")
    source = (root / "yggctl").resolve()
    lines: set[tuple[str, int]] = set()
    arcs: set[tuple[str, int, int]] = set()
    for filename in data.measured_files():
        file = Path(filename).resolve()
        try:
            relative = file.relative_to(source)
        except ValueError:
            continue
        if file.name in {"tests.py", "test_support.py"}:
            continue
        label = str(Path("yggctl") / relative)
        lines.update((label, line) for line in data.lines(filename) or ())
        arcs.update((label, first, second) for first, second in data.arcs(filename) or ())
    if not lines:
        raise RuntimeError("no executed application source lines were recorded")
    return CoveragePoints(frozenset(lines), frozenset(arcs))


def kill_process_group(process: subprocess.Popen) -> None:
    """Kill only the new session created for this round, then reap its child."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_round(
    argv: list[str],
    env: dict[str, str],
    timeout: float,
    *,
    cancelled: Callable[[], int | None] | None = None,
) -> RoundResult:
    """Drain a bounded pipe and enforce the enclosing session's remaining time."""
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(
        argv,
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        bufsize=0,
    )
    selector = None
    count = 0
    assert process.stdout is not None
    try:
        signum = cancelled() if cancelled is not None else None
        if signum is not None:
            kill_process_group(process)
            return RoundResult(128 + signum, count, "interrupted")
        selector = selectors.DefaultSelector()
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            signum = cancelled() if cancelled is not None else None
            if signum is not None:
                kill_process_group(process)
                return RoundResult(128 + signum, count, "interrupted")
            left = deadline - time.monotonic()
            if left <= 0:
                kill_process_group(process)
                return RoundResult(124, count, "round_timeout")
            for key, _ in selector.select(min(left, 0.25)):
                chunk = os.read(key.fd, min(65536, OUTPUT_LIMIT + 1 - count))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                count += len(chunk)
                if count > OUTPUT_LIMIT:
                    kill_process_group(process)
                    return RoundResult(125, count, "output_limit")
        while True:
            signum = cancelled() if cancelled is not None else None
            if signum is not None:
                kill_process_group(process)
                return RoundResult(128 + signum, count, "interrupted")
            left = deadline - time.monotonic()
            if left <= 0:
                kill_process_group(process)
                return RoundResult(124, count, "round_timeout")
            try:
                return RoundResult(process.wait(timeout=min(0.25, left)), count)
            except subprocess.TimeoutExpired:
                continue
    finally:
        if selector is not None:
            selector.close()
        process.stdout.close()
        if process.poll() is None:
            kill_process_group(process)


def write_summary(path: Path, summary: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".plateau-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(summary, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", required=True, type=validate_test_nodeid)
    parser.add_argument("--plateau-seconds", type=bounded_integer(1, MAX_SECONDS), default=7200)
    parser.add_argument("--max-seconds", type=bounded_integer(1, MAX_SECONDS), default=14400)
    parser.add_argument("--round-timeout-seconds", type=bounded_integer(1, 3600), default=300)
    parser.add_argument("--seed", type=bounded_integer(0, MAX_SEED))
    parser.add_argument("--output", type=Path, default=Path("/tmp/fuzz-plateau-summary.json"))
    args = parser.parse_args(argv)
    if args.plateau_seconds > args.max_seconds:
        parser.error("--plateau-seconds must not exceed --max-seconds")

    base_seed = secrets.randbits(64) if args.seed is None else args.seed
    started = time.monotonic()
    progress = CoverageProgress(started, started)
    latest_seed = None
    attempted_rounds = 0
    exit_code, reason = 2, "runner_error"
    previous_handlers = {}
    cancel_signal: int | None = None

    def interrupted(signum, _frame):
        nonlocal cancel_signal
        if cancel_signal is None:
            cancel_signal = signum

    def cancelled():
        return cancel_signal

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, interrupted)
        with tempfile.TemporaryDirectory(prefix="yggctl-plateau-") as temporary:
            coverage_path = Path(temporary) / ".coverage-round"
            env = dict(os.environ)
            env.update(
                YGGCTL_FUZZ_RANDOMIZE="1",
                PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
                PYTHONDONTWRITEBYTECODE="1",
                HYPOTHESIS_STORAGE_DIRECTORY=str(Path(temporary) / "hypothesis"),
            )
            env.pop("PYTEST_ADDOPTS", None)
            env.pop("COVERAGE_PROCESS_START", None)
            while True:
                if cancel_signal is not None:
                    reason, exit_code = "interrupted", 128 + cancel_signal
                    break
                now = time.monotonic()
                stopped = progress.stop_reason(now, args.plateau_seconds, args.max_seconds)
                if stopped:
                    reason, exit_code = stopped, 0
                    break
                latest_seed = (base_seed + attempted_rounds) % (MAX_SEED + 1)
                env["PYTHONHASHSEED"] = str(latest_seed % (2**32))
                attempted_rounds += 1
                coverage_path.unlink(missing_ok=True)
                command = [
                    sys.executable, "-B", "-m", "coverage", "run", "--branch",
                    "--data-file=" + str(coverage_path), "--source=" + str(ROOT / "yggctl"),
                    "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p",
                    "hypothesis.extra.pytestplugin", "--hypothesis-seed=" + str(latest_seed),
                    args.test,
                ]
                print(
                    f"plateau_round_start round={attempted_rounds} seed={latest_seed} "
                    f"test={args.test}", flush=True,
                )
                remaining = progress.remaining(
                    time.monotonic(), args.plateau_seconds, args.max_seconds
                )
                if remaining <= 0:
                    reason = progress.stop_reason(
                        time.monotonic(), args.plateau_seconds, args.max_seconds
                    ) or "max_seconds"
                    exit_code = 0
                    attempted_rounds -= 1
                    break
                result = run_round(
                    command, env, min(args.round_timeout_seconds, remaining),
                    cancelled=cancelled,
                )
                now = time.monotonic()
                if result.stop_reason:
                    stopped = progress.stop_reason(now, args.plateau_seconds, args.max_seconds)
                    if result.stop_reason == "round_timeout" and stopped:
                        reason, exit_code = stopped, 0
                    else:
                        reason, exit_code = result.stop_reason, result.returncode
                    break
                if result.returncode:
                    reason = {
                        1: "test_failure",
                        2: "test_process_interrupted",
                        3: "test_process_internal_error",
                        4: "test_process_usage_error",
                        5: "no_tests",
                    }.get(result.returncode, "test_process_error")
                    if result.returncode < 0:
                        reason = "test_signal"
                    exit_code = result.returncode if result.returncode > 0 else 128 - result.returncode
                    break
                try:
                    points = read_coverage(coverage_path)
                except (CoverageException, OSError, ValueError, RuntimeError):
                    reason, exit_code = "coverage_error", 2
                    break
                new_lines, new_arcs = progress.observe(points, now)
                print(
                    f"plateau_round_end round={attempted_rounds} seed={latest_seed} "
                    f"new_lines={new_lines} new_arcs={new_arcs} "
                    f"lines={len(progress.lines)} arcs={len(progress.arcs)} "
                    f"elapsed_seconds={now - started:.3f}", flush=True,
                )
    except (OSError, ValueError, CoverageException):
        reason, exit_code = "runner_error", 2
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)

    if cancel_signal is not None:
        reason, exit_code = "interrupted", 128 + cancel_signal
    finished = time.monotonic()
    summary = {
        "test": args.test,
        "stop_reason": reason,
        "exit_code": exit_code,
        "rounds": progress.rounds,
        "attempted_rounds": attempted_rounds,
        "covered_lines": len(progress.lines),
        "covered_arcs": len(progress.arcs),
        "elapsed_seconds": round(finished - started, 3),
        "inactive_seconds": round(finished - progress.last_progress_at, 3),
        "plateau_seconds": args.plateau_seconds,
        "max_seconds": args.max_seconds,
        "round_timeout_seconds": args.round_timeout_seconds,
        "base_seed": base_seed,
        "latest_seed": latest_seed,
    }
    try:
        write_summary(args.output, summary)
    except (OSError, ValueError):
        summary["session_stop_reason"] = reason
        summary["session_exit_code"] = exit_code
        summary["stop_reason"] = "summary_write_error"
        summary["exit_code"] = exit_code = 2
    print("plateau_summary " + json.dumps(summary, sort_keys=True, allow_nan=False), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
