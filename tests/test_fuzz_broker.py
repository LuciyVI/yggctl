"""Bounded, synthetic broker properties; no real processes, sockets or host state.

These tests exercise request contracts with a broker object that has never run
its constructor. The context's only effects are mocks inspected by each example.
"""

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from hypothesis import given, settings, strategies as st

import broker
from core import Failure, logged
from fuzz_support import OfflineFuzzCase


PROFILE = settings(max_examples=100, derandomize=True, database=None, deadline=None)
LOCAL_METHODS = ("getself", "getpeers", "gettree", "getpaths", "getsessions")
DEBUG_METHODS = ("debug_remotegetself", "debug_remotegetpeers", "debug_remotegettree")
REMOTE_METHODS = (*DEBUG_METHODS, "getnodeinfo")
ROLES = ("research", "atlas", "remote")
EXPECTED_METHODS = {
    "research": frozenset(LOCAL_METHODS),
    "atlas": frozenset((*LOCAL_METHODS, *DEBUG_METHODS)),
    "remote": frozenset((*LOCAL_METHODS, *REMOTE_METHODS)),
}
JSON_SCALAR = st.one_of(
    st.none(), st.booleans(), st.integers(-(2**63), 2**63 - 1), st.text(max_size=64)
)
JSON_VALUE = st.recursive(
    JSON_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=16), children, max_size=4),
    ),
    max_leaves=12,
)
INVALID_TIMEOUT = st.one_of(
    st.none(),
    st.text(max_size=32),
    st.lists(JSON_SCALAR, max_size=3),
    st.integers(min_value=-(2**31), max_value=0),
    st.integers(min_value=61, max_value=2**31 - 1),
    st.floats(min_value=-1e6, max_value=0.5, allow_nan=False, allow_infinity=False),
    st.floats(min_value=61, max_value=1e6, allow_nan=False, allow_infinity=False),
)


class BrokerFuzzProperties(OfflineFuzzCase):
    @logged
    def server(self, role):
        context = SimpleNamespace(
            p=SimpleNamespace(
                ctl="/synthetic/yggdrasilctl",
                node_sock=Path("/synthetic/node-admin.sock"),
            ),
            run=Mock(return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b"")),
            read_state=Mock(return_value=None),
        )
        server = broker.Broker.__new__(broker.Broker)
        server.ctx, server.role = context, role
        return server

    @logged
    def assert_no_effects(self, server):
        server.ctx.run.assert_not_called()
        server.ctx.read_state.assert_not_called()

    @PROFILE
    @given(
        st.sampled_from(ROLES),
        st.sampled_from((*LOCAL_METHODS, *REMOTE_METHODS)),
        st.binary(min_size=32, max_size=32),
        st.booleans(),
    )
    @logged
    def test_role_method_matrix_builds_only_fixed_endpoint(self, role, method, pin, uppercase):
        server = self.server(role)
        supplied = method.upper() if uppercase else method
        args = [] if method in LOCAL_METHODS else ["key=" + pin.hex()]
        if method not in EXPECTED_METHODS[role]:
            with self.assertRaisesRegex(Failure, "^broker_call_not_allowed$"):
                broker.admin_argv(server.ctx, supplied, args, role)
        else:
            self.assertEqual(
                broker.admin_argv(server.ctx, supplied, args, role),
                [
                    "/synthetic/yggdrasilctl",
                    "-json",
                    "-endpoint=unix:///synthetic/node-admin.sock",
                    supplied,
                    *args,
                ],
            )
        self.assert_no_effects(server)

    @PROFILE
    @given(st.text(max_size=64), st.sampled_from((*LOCAL_METHODS, *REMOTE_METHODS)))
    @logged
    def test_unknown_role_never_builds_a_command(self, suffix, method):
        role = "unknown-role:" + suffix
        server = self.server(role)
        args = [] if method in LOCAL_METHODS else ["key=" + "0" * 64]
        with self.assertRaisesRegex(Failure, "^broker_call_not_allowed$"):
            broker.admin_argv(server.ctx, method, args, role)
        self.assert_no_effects(server)

    @PROFILE
    @given(st.sampled_from(ROLES), st.sampled_from(LOCAL_METHODS), JSON_VALUE)
    @logged
    def test_local_reads_reject_argument_bearing_requests(self, role, method, value):
        server = self.server(role)
        reply = server.handle(json.dumps({"call": "admin", "method": method, "args": [value]}))
        self.assertEqual(reply, {"error": "broker_call_not_allowed"})
        self.assert_no_effects(server)

    @PROFILE
    @given(
        st.sampled_from(REMOTE_METHODS),
        st.one_of(st.binary(max_size=31), st.binary(min_size=33, max_size=40)),
    )
    @logged
    def test_remote_reads_reject_incorrect_key_lengths(self, method, pin):
        server = self.server("remote")
        request = {"call": "admin", "method": method, "args": ["key=" + pin.hex()]}
        self.assertEqual(server.handle(json.dumps(request)), {"error": "broker_call_not_allowed"})
        self.assert_no_effects(server)

    @PROFILE
    @given(st.sampled_from(REMOTE_METHODS), st.lists(JSON_VALUE, min_size=2, max_size=4))
    @logged
    def test_remote_reads_reject_multiple_arguments(self, method, args):
        server = self.server("remote")
        request = {"call": "admin", "method": method, "args": args}
        self.assertEqual(server.handle(json.dumps(request)), {"error": "broker_call_not_allowed"})
        self.assert_no_effects(server)

    @PROFILE
    @given(st.sampled_from(ROLES), INVALID_TIMEOUT)
    @logged
    def test_invalid_timeout_is_rejected_before_any_effect(self, role, timeout):
        server = self.server(role)
        request = {"call": "admin", "method": "getself", "timeout": timeout}
        self.assertEqual(server.handle(json.dumps(request)), {"error": "broker_bad_timeout"})
        self.assert_no_effects(server)

    @PROFILE
    @given(
        st.sampled_from(ROLES),
        st.one_of(st.integers(1, 60), st.floats(min_value=1, max_value=60)),
        st.binary(max_size=512),
        st.binary(max_size=512),
        st.integers(-128, 255),
    )
    @logged
    def test_valid_admin_request_round_trips_opaque_output(self, role, timeout, out, err, rc):
        server = self.server(role)
        server.ctx.run.return_value = SimpleNamespace(returncode=rc, stdout=out, stderr=err)
        request = {"call": "admin", "method": "getself", "timeout": timeout}
        reply = server.handle(json.dumps(request))
        self.assertEqual(set(reply), {"rc", "stdout", "stderr"})
        self.assertEqual(reply["rc"], rc)
        self.assertEqual(base64.b64decode(reply["stdout"], validate=True), out)
        self.assertEqual(base64.b64decode(reply["stderr"], validate=True), err)
        server.ctx.run.assert_called_once_with(
            ["/synthetic/yggdrasilctl", "-json", "-endpoint=unix:///synthetic/node-admin.sock", "getself"],
            timeout=timeout,
            check=False,
        )
        server.ctx.read_state.assert_not_called()

    @PROFILE
    @given(st.integers(0, 255), st.sampled_from((65535, 65536, 65537)), st.binary(max_size=32))
    @logged
    def test_admin_error_stream_is_bounded_before_encoding(self, byte, length, suffix):
        server = self.server("research")
        data = bytes([byte]) * length + suffix
        server.ctx.run.return_value = SimpleNamespace(returncode=1, stdout=b"", stderr=data)
        reply = server.handle(json.dumps({"call": "admin", "method": "getself"}))
        decoded = base64.b64decode(reply["stderr"], validate=True)
        self.assertEqual(decoded, data[:65536])
        self.assertLessEqual(len(decoded), 65536)
        server.ctx.read_state.assert_not_called()

    @PROFILE
    @given(st.sampled_from(ROLES), st.one_of(st.none(), st.binary(max_size=512)), st.text(max_size=64))
    @logged
    def test_metrics_authority_and_filename_are_parent_selected(self, role, data, supplied_name):
        server = self.server(role)
        server.ctx.read_state.return_value = data
        request = {"call": "metrics", "name": supplied_name, "role": "research"}
        reply = server.handle(json.dumps(request))
        if role == "research":
            expected = None if data is None else base64.b64encode(data).decode()
            self.assertEqual(reply, {"data": expected})
            server.ctx.read_state.assert_called_once_with("metrics.jsonl", broker.METRICS_LIMIT)
        else:
            self.assertEqual(reply, {"error": "broker_call_not_allowed"})
            server.ctx.read_state.assert_not_called()
        server.ctx.run.assert_not_called()

    @PROFILE
    @given(
        st.sampled_from(
            (
                ("research", "getnodeinfo"),
                ("research", "debug_remotegetself"),
                ("research", "debug_remotegetpeers"),
                ("research", "debug_remotegettree"),
                ("atlas", "getnodeinfo"),
            )
        ),
        st.binary(min_size=32, max_size=32),
        st.integers(-(2**63), 2**63 - 1),
    )
    @logged
    def test_request_claims_cannot_widen_parent_role(self, pair, pin, claimed_pid):
        role, method = pair
        server = self.server(role)
        request = {
            "call": "admin",
            "method": method,
            "args": ["key=" + pin.hex()],
            "role": "remote",
            "uid": 0,
            "pid": claimed_pid,
        }
        self.assertEqual(server.handle(json.dumps(request)), {"error": "broker_call_not_allowed"})
        self.assert_no_effects(server)

    @PROFILE
    @given(st.sampled_from(ROLES), st.text(max_size=64), JSON_VALUE)
    @logged
    def test_unknown_call_rejects_nested_content_without_effects(self, role, suffix, value):
        server = self.server(role)
        request = {"call": "unknown-call:" + suffix, "data": value}
        self.assertEqual(server.handle(json.dumps(request)), {"error": "broker_call_not_allowed"})
        self.assert_no_effects(server)

    @PROFILE
    @given(st.sampled_from(ROLES), st.one_of(JSON_SCALAR, st.lists(JSON_VALUE, max_size=4)))
    @logged
    def test_non_object_json_rejects_without_effects(self, role, request):
        server = self.server(role)
        self.assertEqual(server.handle(json.dumps(request)), {"error": "broker_bad_request"})
        self.assert_no_effects(server)
