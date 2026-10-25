"""Isolation guards shared by the synthetic, offline fuzz/property tests."""

import os
import unittest
from unittest.mock import patch

from hypothesis import settings


def fuzz_profile(max_examples=100, deadline=None):
    """Keep ordinary runs deterministic; the plateau runner supplies replay seeds."""
    return settings(
        max_examples=max_examples,
        derandomize=os.environ.get("YGGCTL_FUZZ_RANDOMIZE") != "1",
        database=None,
        deadline=deadline,
    )


PROFILE = fuzz_profile()


class OfflineFuzzCase(unittest.TestCase):
    """Fail on process/socket creation and suppress host syslog in each test."""

    def setUp(self):
        super().setUp()
        self.enterContext(patch("core.syslog.syslog"))
        self.enterContext(
            patch("subprocess.Popen", side_effect=AssertionError("offline fuzz: process forbidden"))
        )
        self.enterContext(
            patch("socket.socket", side_effect=AssertionError("offline fuzz: socket forbidden"))
        )
