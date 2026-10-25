"""Bounded file-interface properties, confined to a private temporary directory."""

from pathlib import Path
import stat
import tempfile

from hypothesis import given, strategies as st

from core import Failure, atomic, read_regular
from fuzz_support import OfflineFuzzCase, PROFILE


class StateIoFuzzProperties(OfflineFuzzCase):
    @PROFILE
    @given(data=st.binary(max_size=512), limit=st.integers(min_value=0, max_value=512))
    def test_bounded_read_returns_all_bytes_or_fixed_failure(self, data, limit):
        with tempfile.TemporaryDirectory(prefix="yggctl-fuzz-") as directory:
            path = Path(directory) / "record"
            path.write_bytes(data)
            if len(data) <= limit:
                self.assertEqual(read_regular(path, limit=limit), data)
            else:
                with self.assertRaisesRegex(Failure, "^file_size_limit$"):
                    read_regular(path, limit=limit)
            self.assertEqual(path.read_bytes(), data)

    @PROFILE
    @given(
        values=st.lists(st.binary(max_size=256), min_size=1, max_size=5),
        mode=st.sampled_from((0o600, 0o640, 0o644)),
    )
    def test_repeated_atomic_publication_preserves_bytes_mode_and_inventory(self, values, mode):
        with tempfile.TemporaryDirectory(prefix="yggctl-fuzz-") as directory:
            parent = Path(directory)
            path = parent / "record"
            for data in values:
                atomic(path, data, mode=mode)
                self.assertEqual(read_regular(path, limit=256), data)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                self.assertEqual({member.name for member in parent.iterdir()}, {"record"})

    @PROFILE
    @given(original=st.binary(max_size=256), replacement=st.binary(max_size=256))
    def test_atomic_rejects_symlink_leaf_without_changing_its_target(self, original, replacement):
        with tempfile.TemporaryDirectory(prefix="yggctl-fuzz-") as directory:
            parent = Path(directory)
            target, link = parent / "target", parent / "record"
            target.write_bytes(original)
            link.symlink_to(target.name)
            with self.assertRaisesRegex(Failure, "^unsafe_atomic_path$"):
                atomic(link, replacement)
            self.assertTrue(link.is_symlink())
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual({member.name for member in parent.iterdir()}, {"target", "record"})
