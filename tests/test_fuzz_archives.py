"""Small in-memory archive properties; no extraction, GPG, host files or processes."""

import io
import json
import tarfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hypothesis import given, settings, strategies as st

from core import Failure, FILES, KEYS, NODE, STACK, TIMER, digest, logged
from fuzz_support import OfflineFuzzCase
import recovery


PROFILE = settings(max_examples=60, derandomize=True, database=None, deadline=None)
REQUIRED = tuple("config/" + name for name in FILES) + tuple(
    "units/" + name for name in (NODE, STACK, TIMER, "ygg-metrics.service")
)
KEY_MEMBERS = tuple("keys/" + name for name in KEYS)
CONTENTS = st.lists(st.binary(max_size=128), min_size=len(REQUIRED), max_size=len(REQUIRED))


@logged
def archive_fixture(files, *, special=None, hashes=None):
    """Create only small fixture TAR entries, with an independent manifest."""
    manifest = {
        "schema": 1,
        "keys": False,
        "sha256": hashes
        if hashes is not None
        else {name: digest(data) for name, data in files.items()},
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, value in dict(files, **{"manifest.json": json.dumps(manifest).encode()}).items():
            info = tarfile.TarInfo(name)
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
        if special is not None:
            archive.addfile(special)
    return output.getvalue()


class ArchiveFuzzProperties(OfflineFuzzCase):
    @PROFILE
    @given(CONTENTS, st.booleans(), st.binary(max_size=64), st.binary(max_size=64))
    @logged
    def test_generated_backups_preserve_all_member_bytes(self, values, full, first, second):
        files = dict(zip(REQUIRED, values))
        if full:
            files.update(zip(KEY_MEMBERS, (first, second)))
        recovered, has_keys = recovery.inspect_archive(recovery.archive(files, full=full))
        self.assertEqual(recovered, files)
        self.assertIs(has_keys, full)

    @PROFILE
    @given(CONTENTS, st.sampled_from(REQUIRED))
    @logged
    def test_changed_member_bytes_do_not_match_the_original_manifest(self, values, changed):
        files = dict(zip(REQUIRED, values))
        hashes = {name: digest(data) for name, data in files.items()}
        files[changed] += b"fixture"
        with self.assertRaisesRegex(Failure, "^backup_member_hash_mismatch$"):
            recovery.inspect_archive(archive_fixture(files, hashes=hashes))

    @PROFILE
    @given(CONTENTS, st.sampled_from(REQUIRED))
    @logged
    def test_valid_hashes_do_not_allow_missing_required_members(self, values, missing):
        files = dict(zip(REQUIRED, values))
        del files[missing]
        with self.assertRaisesRegex(Failure, "^backup_members_missing$"):
            recovery.inspect_archive(archive_fixture(files))

    @PROFILE
    @given(CONTENTS, st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=16))
    @logged
    def test_regular_members_outside_the_fixed_inventory_are_refused(self, values, label):
        files = dict(zip(REQUIRED, values))
        files[f"fixture/{label}.txt"] = b"synthetic fixture"
        with self.assertRaisesRegex(Failure, "^unsafe_archive_member$"):
            recovery.inspect_archive(archive_fixture(files))

    @PROFILE
    @given(CONTENTS, st.sampled_from(REQUIRED), st.sampled_from((tarfile.DIRTYPE, tarfile.SYMTYPE)))
    @logged
    def test_allowlisted_names_still_require_regular_file_members(self, values, selected, kind):
        files = dict(zip(REQUIRED, values))
        del files[selected]
        special = tarfile.TarInfo(selected)
        special.type = kind
        if kind == tarfile.SYMTYPE:
            special.linkname = "fixture-relative"
        with self.assertRaisesRegex(Failure, "^unsafe_archive_member$"):
            recovery.inspect_archive(archive_fixture(files, special=special))

    @PROFILE
    @given(st.text(max_size=128))
    @logged
    def test_restore_apply_is_refused_before_path_or_process_access(self, path):
        ctx = SimpleNamespace(root=Mock(), locked=Mock(), run=Mock())
        with (
            patch.object(recovery, "read_regular") as reader,
            self.assertRaisesRegex(
                Failure, "^restore_apply_requires_independent_authentication_review$"
            ),
        ):
            recovery.restore(ctx, path, apply=True)
        ctx.root.assert_called_once_with()
        ctx.locked.assert_not_called()
        ctx.run.assert_not_called()
        reader.assert_not_called()
