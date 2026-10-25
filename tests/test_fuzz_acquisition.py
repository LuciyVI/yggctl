"""Bounded, deterministic acquisition properties; no live catalogue or mesh calls."""

import io
import json
import string
from types import SimpleNamespace
from unittest.mock import Mock
import urllib.parse
import zipfile

from hypothesis import given, settings, strategies as st

from atlas import catalogue, protocol
from core import Failure, logged
from fuzz_support import OfflineFuzzCase


PROFILE = settings(max_examples=80, derandomize=True, database=None, deadline=None)
KEY = st.binary(min_size=32, max_size=32).map(bytes.hex)
LABEL = st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=12)
TEXT = st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=16)
TRANSPORT = st.sampled_from(("tcp", "tls", "quic", "ws", "wss"))


class AcquisitionFuzzProperties(OfflineFuzzCase):
    @PROFILE
    @given(TRANSPORT, LABEL, st.integers(1, 65535), KEY, TEXT, TEXT)
    @logged
    def test_catalogue_projection_keeps_only_typed_endpoint_fields(
        self, transport, host, port, pin, user, metadata
    ):
        query = urllib.parse.urlencode(
            [("key", pin.upper()), ("key", pin), ("password", metadata), ("fixture", metadata)]
        )
        uri = f"{transport}://{user}@{host}.example.invalid:{port}/{metadata}?{query}"
        row = catalogue.endpoint(uri)

        self.assertEqual(
            set(row),
            {
                "id",
                "endpoint",
                "transport",
                "pins",
                "path_omitted",
                "authentication_omitted",
            },
        )
        self.assertEqual(row["endpoint"], f"{transport}://{host}.example.invalid:{port}")
        self.assertEqual(row["transport"], transport)
        self.assertEqual(row["pins"], [pin])
        self.assertTrue(row["path_omitted"])
        self.assertTrue(row["authentication_omitted"])

    @PROFILE
    @given(
        st.binary(min_size=20, max_size=20).map(bytes.hex),
        LABEL,
        st.lists(st.tuples(TRANSPORT, st.integers(1, 65535), KEY), min_size=1, max_size=8),
        st.binary(max_size=128),
    )
    @logged
    def test_repository_zip_projects_matching_markdown_and_ignores_other_members(
        self, commit, region, peers, ignored
    ):
        uris = [f"{scheme}://peer.example.invalid:{port}?key={pin}" for scheme, port, pin in peers]
        body = "\n".join(f"`{uri}`" for uri in uris).encode()
        output = io.BytesIO()
        # Stored entries keep the generated input budget independent of compression.
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(f"public-peers-{commit}/fixture/{region}.md", body)
            archive.writestr(f"public-peers-{commit}/fixture/notes.txt", ignored)

        rows, invalid = catalogue.repository_rows(output.getvalue(), commit)
        self.assertEqual(invalid, 0)
        self.assertEqual(len(rows), len(uris))
        for row, uri in zip(rows, uris):
            expected = catalogue.endpoint(uri)
            self.assertEqual({key: row[key] for key in expected}, expected)
            self.assertEqual(row["countries"], [region])
            self.assertEqual(row["sources"], [f"repository:fixture/{region}.md"])
            self.assertIsNone(row["registry_online"])
            self.assertIsNone(row["registry_uptime7d_pct"])

    @PROFILE
    @given(
        st.one_of(
            st.sampled_from((catalogue.API, catalogue.MONITOR)),
            st.binary(min_size=20, max_size=20).map(
                lambda value: "https://codeload.github.com/yggdrasil-network/public-peers/zip/"
                + value.hex()
            ),
        ),
        st.binary(max_size=256),
    )
    @logged
    def test_fixed_catalogue_sources_use_only_the_stubbed_runner(self, url, body):
        ctx = SimpleNamespace(run=Mock(return_value=SimpleNamespace(stdout=body)))
        self.assertEqual(catalogue.fetch(ctx, url), body)
        ctx.run.assert_called_once()
        argv = ctx.run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/curl")
        self.assertEqual(argv[-1], url)
        self.assertEqual(argv[argv.index("--proto") + 1], "=https")
        self.assertEqual(ctx.run.call_args.kwargs["timeout"], 27)

    @PROFILE
    @given(LABEL, TEXT)
    @logged
    def test_nonfixed_sources_are_rejected_before_runner_access(self, host, suffix):
        ctx = SimpleNamespace(run=Mock(side_effect=AssertionError("unexpected runner call")))
        urls = (
            f"https://{host}.example.invalid/{suffix}",
            catalogue.API + "?fixture=" + suffix,
            catalogue.MONITOR + "#fixture-" + suffix,
        )
        for url in urls:
            with self.subTest(url=url), self.assertRaisesRegex(
                Failure, "^atlas_nonfixed_source_rejected$"
            ):
                catalogue.fetch(ctx, url)
        ctx.run.assert_not_called()

    @PROFILE
    @given(KEY, st.sampled_from(("peers", "tree")), st.lists(KEY, max_size=24))
    @logged
    def test_remote_key_lists_preserve_multiplicity_without_inventing_evidence(
        self, target, method, keys
    ):
        reply = {protocol.address(target): {"keys": [key.upper() for key in keys]}}
        row = protocol.projection(target, method, reply)
        self.assertEqual(row["keys"], sorted(set(keys)))
        self.assertEqual(row["returned_rows"], len(keys))
        self.assertEqual(row["duplicate_rows"], len(keys) - len(set(keys)))
        self.assertIsNone(row["complete"])
        self.assertEqual(
            row["semantics"],
            "reported_peers_no_up_or_latency"
            if method == "peers"
            else "tree_key_references_NO_parent_edges",
        )

    @PROFILE
    @given(KEY, st.sampled_from(("self", "peers", "tree")), st.integers(0, 2**32))
    @logged
    def test_remote_envelope_with_an_extra_target_is_refused(self, target, method, count):
        body = {"key": target, "routing_entries": count} if method == "self" else {"keys": []}
        reply = {protocol.address(target): body, "fixture.example.invalid": {}}
        with self.assertRaisesRegex(Failure, "^atlas_remote_target_envelope_mismatch$"):
            protocol.projection(target, method, reply)

    @PROFILE
    @given(KEY, st.sampled_from(("self", "peers", "tree")), st.binary(max_size=256))
    @logged
    def test_query_invalid_json_remains_unknown_without_raw_response(self, target, method, data):
        ctx = SimpleNamespace(
            p=SimpleNamespace(ctl="/fixture/yggdrasilctl", node_sock="/fixture/admin.sock"),
            run=Mock(return_value=SimpleNamespace(stdout=b"fixture:" + data)),
        )
        status, elapsed, value = protocol.query(ctx, target, method)
        self.assertEqual(status, "unknown")
        self.assertIsNone(value)
        self.assertGreaterEqual(elapsed, 0)
        ctx.run.assert_called_once()
        self.assertEqual(ctx.run.call_args.kwargs["timeout"], 8)

    @PROFILE
    @given(KEY, st.sampled_from(("peers", "tree")), st.lists(KEY, max_size=16))
    @logged
    def test_query_valid_json_exposes_only_the_projection(self, target, method, keys):
        reply = {protocol.address(target): {"keys": keys}}
        ctx = SimpleNamespace(
            p=SimpleNamespace(ctl="/fixture/yggdrasilctl", node_sock="/fixture/admin.sock"),
            run=Mock(return_value=SimpleNamespace(stdout=json.dumps(reply).encode())),
        )
        status, elapsed, value = protocol.query(ctx, target, method)
        self.assertEqual(status, "ok")
        self.assertGreaterEqual(elapsed, 0)
        self.assertEqual(value, protocol.projection(target, method, reply))
