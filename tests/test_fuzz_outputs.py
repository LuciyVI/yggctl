"""Bounded synthetic output properties; no browser, network or live sender.

These tests exercise projection and serialization contracts only. Parsing the
generated HTML with HTMLParser does not execute JavaScript or qualify a browser.
"""

import copy
from html.parser import HTMLParser
import json
from typing import Any

from hypothesis import given, strategies as st

from atlas import viewer
from core import Failure, logged
from fuzz_support import OfflineFuzzCase, fuzz_profile
import telemetry


PROFILE = fuzz_profile(deadline=1000)
TEXT = st.text(max_size=256)
JSON_SCALAR = st.one_of(
    st.none(), st.booleans(), st.integers(min_value=-10**9, max_value=10**9), st.text(max_size=80)
)
EXTRA_FIELDS = st.dictionaries(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12).map(
        lambda name: "extra_" + name
    ),
    JSON_SCALAR,
    max_size=8,
)
MARKUP_TEXT = st.text(alphabet="<>&\"' /abcXYZ012\u2028\u2029", max_size=100)


class DocumentProjection(HTMLParser):
    """Observe markup structure and embedded JSON without running a browser."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict[str, str | None]] = []
        self.policies: list[str] = []
        self.payload: list[str] = []
        self.in_payload = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "script":
            self.scripts.append(attributes)
            self.in_payload = attributes.get("id") == "atlas-data"
        if tag == "meta" and attributes.get("http-equiv") == "Content-Security-Policy":
            self.policies.append(attributes.get("content") or "")

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_payload = False

    def handle_data(self, data):
        if self.in_payload:
            self.payload.append(data)


def document_data(label: str, text: str) -> dict[str, Any]:
    """Small projected graph; untrusted text stays data in the offline viewer."""
    return {
        "generated": "2026-10-25T00:00:00+00:00",
        "respondent_keys": 1,
        "catalogue": [],
        "countries": {
            "claim-" + label: {
                "endpoints": 1,
                "pin_keys": 1,
                "registry_online": 0,
                "registry_offline": 0,
                "registry_unknown": 1,
            }
        },
        "limits": [text],
        "nodes": [
            {
                "key": "a" * 64,
                "roles": ["validated_payload_respondent"],
                "observed_peer_degree": 0,
                # A future projected string must remain script-safe as promised
                # by viewer.html, even though the UI does not consume it today.
                "label": text,
            }
        ],
        "edges": [],
    }


class OutputFuzzProperties(OfflineFuzzCase):
    @PROFILE
    @given(st.text(min_size=1, max_size=128), EXTRA_FIELDS)
    @logged
    def test_explicit_alert_identity_is_preserved_without_mutation(self, identity, extra):
        alert = {"id": identity, **extra}
        before = copy.deepcopy(alert)
        self.assertEqual(telemetry.alert_id(alert), identity)
        self.assertEqual(alert, before)

    @PROFILE
    @given(EXTRA_FIELDS)
    @logged
    def test_legacy_alert_identity_is_independent_of_object_key_order(self, fields):
        alert = {"kind": "labelled-local-selftest", "ts": "synthetic", **fields}
        reordered = dict(reversed(list(alert.items())))
        before = copy.deepcopy(alert)
        identity = telemetry.alert_id(alert)
        self.assertRegex(identity, r"^[0-9a-f]{16}$")
        self.assertEqual(telemetry.alert_id(reordered), identity)
        self.assertEqual(alert, before)

    @PROFILE
    @given(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(min_value=-10**9, max_value=10**9),
            st.lists(st.integers(min_value=-100, max_value=100), max_size=4),
            st.just(""),
            st.text(min_size=129, max_size=180),
        )
    )
    @logged
    def test_invalid_explicit_identity_is_rejected(self, identity):
        with self.assertRaisesRegex(Failure, "^invalid_alert_id$"):
            telemetry.alert_id({"id": identity})

    @PROFILE
    @given(
        st.sampled_from(tuple(telemetry.MESSAGES)),
        TEXT,
        st.lists(TEXT, max_size=8),
        EXTRA_FIELDS,
    )
    @logged
    def test_alert_envelope_is_bounded_and_unknown_fields_have_no_authority(
        self, kind, timestamp, errors, extra
    ):
        alert = {
            "kind": kind,
            "ts": timestamp,
            "peer": "tls://192.0.2.10:443",
            "minutes": 11,
            "up": 1,
            "total": 2,
            "count": 3,
            "errors": errors,
        }
        before = copy.deepcopy(alert)
        message = telemetry.alert_message(alert)
        self.assertEqual(telemetry.alert_message({**alert, **extra}), message)
        self.assertEqual(set(message), {"rule", "priority", "output", "source", "time"})
        self.assertTrue(all(isinstance(value, str) for value in message.values()))
        self.assertEqual(message["source"], "yggctl")
        self.assertIn(message["priority"], {"Warning", "Error"})
        self.assertLessEqual(len(message["output"]), 300)
        self.assertEqual(message["time"], timestamp[:40])
        self.assertEqual(json.loads(json.dumps(message, allow_nan=False)), message)
        self.assertEqual(alert, before)

    @PROFILE
    @given(
        st.sampled_from(("ygg-peer-down", "ygg-peer-up", "ygg-peer-unstable")),
        st.sampled_from(("tls", "tcp", "quic", "ws", "wss")),
        st.sampled_from(("query", "path", "fragment", "userinfo")),
        st.binary(min_size=1, max_size=24),
        st.integers(min_value=1, max_value=65535),
    )
    @logged
    def test_peer_alerts_remove_private_uri_metadata_before_rendering(
        self, kind, scheme, location, raw_secret, port
    ):
        secret = "synthetic-private-" + raw_secret.hex()
        endpoint = f"{scheme}://192.0.2.10:{port}"
        if location == "userinfo":
            peer = f"{scheme}://user:{secret}@192.0.2.10:{port}"
        else:
            metadata = {
                "query": "?key=" + "a" * 64 + "&token=" + secret,
                "path": "/private/" + secret,
                "fragment": "#" + secret,
            }
            peer = endpoint + metadata[location]
        alert = {
            "kind": kind,
            "peer": peer,
            "minutes": 11,
            "up": 1,
            "total": 2,
            "count": 3,
        }
        before = copy.deepcopy(alert)
        rendered = telemetry.alert_message(alert)
        self.assertNotIn(secret, json.dumps(rendered))
        self.assertIn(endpoint, rendered["rule"])
        self.assertIn(endpoint, rendered["output"])
        self.assertEqual(alert, before)

    @PROFILE
    @given(MARKUP_TEXT, TEXT)
    @logged
    def test_viewer_text_stays_in_inert_markup_and_roundtrips_as_json(self, label, text):
        data = document_data(label, text)
        before = copy.deepcopy(data)
        page = viewer.html(data)
        parsed = DocumentProjection()
        parsed.feed(page)
        parsed.close()
        self.assertEqual(len(parsed.scripts), 2)
        self.assertTrue(all("src" not in attrs for attrs in parsed.scripts))
        self.assertEqual(parsed.scripts[0].get("id"), "atlas-data")
        self.assertEqual(parsed.scripts[0].get("type"), "application/json")
        payload = "".join(parsed.payload)
        self.assertNotRegex(payload, r"[<>&]")
        self.assertEqual(json.loads(payload), {"nodes": data["nodes"], "edges": []})
        self.assertEqual(len(parsed.policies), 1)
        directives = {
            parts[0]: parts[1:]
            for clause in parsed.policies[0].split(";")
            if (parts := clause.split())
        }
        for directive in ("default-src", "connect-src", "base-uri", "form-action"):
            self.assertEqual(directives[directive], ["'none'"])
        self.assertEqual(data, before)

    @PROFILE
    @given(st.sampled_from((float("nan"), float("inf"), float("-inf"))))
    @logged
    def test_viewer_refuses_nonfinite_graph_json(self, number):
        data = document_data("synthetic", "synthetic")
        data["nodes"][0]["observed_peer_degree"] = number
        with self.assertRaises(ValueError):
            viewer.html(data)
