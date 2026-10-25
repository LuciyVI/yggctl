"""Generated peer-input boundary checks; no DNS or network operations."""

from urllib.parse import parse_qs, urlencode, urlsplit

from hypothesis import given, strategies as st

from core import Failure, peer_uri
from fuzz_support import OfflineFuzzCase, PROFILE


PIN = st.binary(min_size=32, max_size=32).map(bytes.hex)
OCTET = st.integers(min_value=1, max_value=254)
PORT = st.integers(min_value=1, max_value=65535)


class PeerInputFuzzProperties(OfflineFuzzCase):
    @PROFILE
    @given(
        data=st.data(),
        scheme=st.sampled_from(("tls", "tcp", "quic")),
        octet=OCTET,
        port=PORT,
        pin=PIN,
        priority=st.integers(min_value=0, max_value=255),
        backoff=st.integers(min_value=0, max_value=99999),
        unit=st.sampled_from(("ms", "s", "m", "h")),
    )
    def test_valid_option_order_does_not_change_canonical_peer(
        self, data, scheme, octet, port, pin, priority, backoff, unit
    ):
        options = (
            ("key", pin.upper()),
            ("priority", str(priority)),
            ("maxbackoff", f"{backoff}{unit}"),
            ("sni", "peer.example.invalid"),
        )
        shuffled = data.draw(st.permutations(options))
        base = f"{scheme}://192.0.2.{octet}:{port}"
        canonical, endpoint = peer_uri(base + "?" + urlencode(shuffled))
        self.assertEqual(peer_uri(base + "?" + urlencode(options)), (canonical, endpoint))
        self.assertEqual(endpoint, f"192.0.2.{octet}:{port}")
        self.assertEqual(urlsplit(canonical).scheme, scheme)
        self.assertEqual(
            parse_qs(urlsplit(canonical).query),
            {
                "key": [pin],
                "priority": [str(priority)],
                "maxbackoff": [f"{backoff}{unit}"],
                "sni": ["peer.example.invalid"],
            },
        )

    @PROFILE
    @given(
        label=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=32),
        scheme=st.sampled_from(("tls", "tcp", "quic", "ws", "wss")),
        port=PORT,
        pin=PIN,
        force=st.booleans(),
    )
    def test_force_does_not_admit_dns_selectors(self, label, scheme, port, pin, force):
        uri = f"{scheme}://{label}.invalid:{port}?key={pin}"
        with self.assertRaisesRegex(Failure, "^ipv4_literal_required$"):
            peer_uri(uri, force=force)

    @PROFILE
    @given(data=st.data(), control=st.sampled_from(("\x00", "\x1f", "\n", "\r", "\t", " ")))
    def test_control_or_whitespace_insertion_is_always_rejected(self, data, control):
        uri = "tls://192.0.2.1:443?key=" + data.draw(PIN)
        position = data.draw(st.integers(min_value=0, max_value=len(uri)))
        raw = uri[:position] + control + uri[position:]
        with self.assertRaisesRegex(Failure, "^invalid_peer_uri$"):
            peer_uri(raw)

    @PROFILE
    @given(first=PIN, second=PIN, octet=OCTET, port=PORT)
    def test_duplicate_pins_are_rejected_even_when_equal(self, first, second, octet, port):
        query = urlencode((("key", first), ("key", second)))
        with self.assertRaisesRegex(Failure, "^one_valid_key_pin_required$"):
            peer_uri(f"tls://192.0.2.{octet}:{port}?{query}")

    @PROFILE
    @given(scheme=st.sampled_from(("ws", "wss")), octet=OCTET, port=PORT, pin=PIN)
    def test_websocket_peers_require_explicit_force(self, scheme, octet, port, pin):
        uri = f"{scheme}://192.0.2.{octet}:{port}/peer?key={pin}"
        with self.assertRaisesRegex(Failure, "^ws_wss_require_force$"):
            peer_uri(uri)
        canonical, endpoint = peer_uri(uri, force=True)
        self.assertEqual(endpoint, f"192.0.2.{octet}:{port}")
        self.assertEqual(urlsplit(canonical).path, "/peer")
        self.assertEqual(parse_qs(urlsplit(canonical).query)["key"], [pin])
