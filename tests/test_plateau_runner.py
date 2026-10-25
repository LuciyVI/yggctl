"""Pure coverage-clock and selector contracts; no sessions or child processes run."""

import argparse
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import fuzz_plateau as runner


ROOT = Path(__file__).resolve().parents[1]
NODE = (
    "tests/test_fuzz_broker.py::BrokerFuzzProperties::"
    "test_request_claims_cannot_widen_parent_role"
)


def coverage_points(lines=(), arcs=()):
    return runner.CoveragePoints(frozenset(lines), frozenset(arcs))


class PlateauRunnerContracts(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.enterContext(
            patch("subprocess.Popen", side_effect=AssertionError("no child process in unit fixture"))
        )
        self.enterContext(
            patch("socket.socket", side_effect=AssertionError("no socket in unit fixture"))
        )

    def test_first_coverage_establishes_progress_and_union(self):
        progress = runner.CoverageProgress(started_at=100, last_progress_at=100)
        points = coverage_points(
            lines={("core.py", 10), ("core.py", 11)},
            arcs={("core.py", 10, 11)},
        )
        self.assertEqual(progress.observe(points, now=110), (2, 1))
        self.assertEqual(progress.last_progress_at, 110)
        self.assertEqual(progress.lines, points.lines)
        self.assertEqual(progress.arcs, points.arcs)
        self.assertEqual(progress.rounds, 1)

    def test_identical_coverage_does_not_extend_inactivity_deadline(self):
        progress = runner.CoverageProgress(started_at=100, last_progress_at=100)
        points = coverage_points(lines={("core.py", 10)}, arcs=set())
        progress.observe(points, now=110)
        self.assertEqual(progress.observe(points, now=180), (0, 0))
        self.assertEqual(progress.last_progress_at, 110)
        self.assertIsNone(progress.stop_reason(now=229, plateau_seconds=120, max_seconds=500))
        self.assertEqual(
            progress.stop_reason(now=230, plateau_seconds=120, max_seconds=500), "plateau"
        )

    def test_new_line_resets_plateau_timer(self):
        progress = runner.CoverageProgress(started_at=0, last_progress_at=0)
        progress.observe(coverage_points(lines={("core.py", 10)}, arcs=set()), now=10)
        self.assertEqual(
            progress.observe(
                coverage_points(lines={("core.py", 11)}, arcs=set()), now=100
            ),
            (1, 0),
        )
        self.assertEqual(progress.last_progress_at, 100)
        self.assertIsNone(progress.stop_reason(now=219, plateau_seconds=120, max_seconds=500))

    def test_new_arc_resets_timer_even_when_no_new_line_is_covered(self):
        progress = runner.CoverageProgress(started_at=0, last_progress_at=0)
        lines = {("core.py", 10), ("core.py", 11)}
        progress.observe(coverage_points(lines=lines, arcs=set()), now=10)
        self.assertEqual(
            progress.observe(
                coverage_points(lines=lines, arcs={("core.py", 10, 11)}), now=100
            ),
            (0, 1),
        )
        self.assertEqual(progress.last_progress_at, 100)

    def test_smaller_round_does_not_erase_union_or_claim_progress(self):
        progress = runner.CoverageProgress(started_at=0, last_progress_at=0)
        lines = {("core.py", 10), ("core.py", 11)}
        arcs = {("core.py", 10, 11), ("core.py", 11, -1)}
        progress.observe(coverage_points(lines=lines, arcs=arcs), now=10)
        self.assertEqual(
            progress.observe(
                coverage_points(lines={("core.py", 10)}, arcs=set()), now=100
            ),
            (0, 0),
        )
        self.assertEqual(progress.lines, lines)
        self.assertEqual(progress.arcs, arcs)
        self.assertEqual(progress.last_progress_at, 10)

    def test_coverage_identity_includes_filename_not_just_point_count(self):
        progress = runner.CoverageProgress(started_at=0, last_progress_at=0)
        progress.observe(
            coverage_points(lines={("core.py", 10)}, arcs={("core.py", 10, 11)}),
            now=10,
        )
        self.assertEqual(
            progress.observe(
                coverage_points(
                    lines={("broker.py", 10)}, arcs={("broker.py", 10, 11)}
                ),
                now=100,
            ),
            (1, 1),
        )
        self.assertEqual(len(progress.lines), 2)
        self.assertEqual(len(progress.arcs), 2)
        self.assertEqual(progress.last_progress_at, 100)

    def test_total_budget_is_independent_of_recent_coverage_progress(self):
        progress = runner.CoverageProgress(started_at=0, last_progress_at=180)
        self.assertIsNone(progress.stop_reason(now=199, plateau_seconds=120, max_seconds=200))
        self.assertEqual(
            progress.stop_reason(now=200, plateau_seconds=120, max_seconds=200), "max_seconds"
        )

    def test_remaining_uses_earlier_deadline_and_never_becomes_negative(self):
        progress = runner.CoverageProgress(started_at=0, last_progress_at=110)
        self.assertEqual(progress.remaining(now=150, plateau_seconds=120, max_seconds=300), 80)
        self.assertEqual(progress.remaining(now=250, plateau_seconds=120, max_seconds=300), 0)
        progress.last_progress_at = 280
        self.assertEqual(progress.remaining(now=290, plateau_seconds=120, max_seconds=300), 10)

    def test_selected_authored_test_node_is_accepted(self):
        self.assertEqual(runner.validate_test_nodeid(NODE, root=ROOT), NODE)

    def test_selectors_outside_the_single_offline_property_contract_are_rejected(self):
        invalid = (
            "tests/test_fuzz_broker.py",
            "tests/test_fuzz_broker.py::BrokerFuzzProperties",
            "tests/test_fuzz_broker.py::BrokerFuzzProperties::server",
            "tests/test_cli_edges.py::CliEdges::test_information_and_readonly_handlers",
            "../tests/test_fuzz_broker.py::BrokerFuzzProperties::"
            "test_request_claims_cannot_widen_parent_role",
            "-k broker",
            NODE + " extra",
            str(ROOT / "tests/test_fuzz_broker.py")
            + "::BrokerFuzzProperties::test_request_claims_cannot_widen_parent_role",
        )
        for selector in invalid:
            with self.subTest(selector=selector), self.assertRaises(argparse.ArgumentTypeError):
                runner.validate_test_nodeid(selector, root=ROOT)
