"""Isolation guards shared by the synthetic, offline fuzz/property tests."""

import unittest
from unittest.mock import patch

from hypothesis import settings


PROFILE = settings(max_examples=100, derandomize=True, database=None, deadline=None)


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
