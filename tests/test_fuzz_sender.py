"""Bounded SimpleX preflight properties with all profile and send operations mocked."""

import contextlib
import hashlib
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hypothesis import given, strategies as st

from core import Failure
from fuzz_support import OfflineFuzzCase, PROFILE
import simplex_sender as sender


TEXT = st.text(max_size=48)
EVENT = st.text(min_size=1, max_size=128)
NUMBER = st.integers(-(2**63), 2**63 - 1)
NONSTRING = st.one_of(st.none(), st.booleans(), NUMBER, st.lists(NUMBER, max_size=3))
FIELDS = ("source", "rule", "output", "priority", "time")
BINDING = "b" * 64


def payload(rule="synthetic rule", output="synthetic output"):
    return {
        "source": "yggctl",
        "rule": rule,
        "output": output,
        "priority": "Warning",
        "time": "synthetic time",
    }


def message(event_id, value):
    key = hashlib.sha256(event_id.encode()).hexdigest()
    text = "[yggctl:" + key + "]\n" + value["rule"] + "\n" + value["output"]
    return key, text, hashlib.sha256(text.encode()).hexdigest()


@contextlib.contextmanager
def mocked_profile(*, journal=None, item=17):
    """Even an unexpected downstream branch cannot reach a real profile or process."""
    ctx = SimpleNamespace(
        root=Mock(),
        run=Mock(side_effect=AssertionError("native execution forbidden in this fixture")),
    )
    cfg = {"lock": "/synthetic/profile.lock"}
    with contextlib.ExitStack() as stack:
        operations = SimpleNamespace(
            configuration=stack.enter_context(patch.object(sender, "configuration", return_value=cfg)),
            lock=stack.enter_context(
                patch.object(sender, "profile_lock", return_value=contextlib.nullcontext(19))
            ),
            lookup=stack.enter_context(
                patch.object(sender, "lookup", return_value=(BINDING, 7, item))
            ),
            load=stack.enter_context(
                patch.object(sender, "load_journal", return_value={} if journal is None else journal)
            ),
            save=stack.enter_context(patch.object(sender, "save_journal")),
        )
        # A mistaken send branch must stop before account lookup or execution.
        stack.enter_context(
            patch.object(
                sender.pwd,
                "getpwnam",
                side_effect=AssertionError("account lookup forbidden in this fixture"),
            )
        )
        yield ctx, operations


class SenderFuzzProperties(OfflineFuzzCase):
    def assert_no_profile_work(self, ctx, operations):
        ctx.root.assert_called_once_with()
        operations.configuration.assert_not_called()
        operations.lock.assert_not_called()
        operations.lookup.assert_not_called()
        operations.load.assert_not_called()
        operations.save.assert_not_called()
        ctx.run.assert_not_called()

    @PROFILE
    @given(event_id=EVENT, value=st.one_of(NONSTRING, TEXT))
    def test_nonobject_events_fail_before_profile_access(self, event_id, value):
        with mocked_profile() as (ctx, operations):
            with self.assertRaisesRegex(Failure, "^simplex_event_schema$"):
                sender.handoff(ctx, event_id, value)
            self.assert_no_profile_work(ctx, operations)

    @PROFILE
    @given(event_id=EVENT, field=st.sampled_from(("rule", "output", "priority", "time")), value=NONSTRING)
    def test_nonstring_required_fields_never_reach_profile(self, event_id, field, value):
        event = payload()
        event[field] = value
        with mocked_profile() as (ctx, operations):
            with self.assertRaisesRegex(Failure, "^simplex_event_schema$"):
                sender.handoff(ctx, event_id, event)
            self.assert_no_profile_work(ctx, operations)

    @PROFILE
    @given(event_id=EVENT, missing=st.sets(st.sampled_from(FIELDS), min_size=1))
    def test_missing_fields_never_reach_profile(self, event_id, missing):
        event = {key: value for key, value in payload().items() if key not in missing}
        with mocked_profile() as (ctx, operations):
            with self.assertRaisesRegex(Failure, "^simplex_event_schema$"):
                sender.handoff(ctx, event_id, event)
            self.assert_no_profile_work(ctx, operations)

    @PROFILE
    @given(
        event_id=st.one_of(NONSTRING, st.just(""), st.text(min_size=129, max_size=160)),
        rule=TEXT,
        output=TEXT,
    )
    def test_invalid_event_ids_never_reach_profile(self, event_id, rule, output):
        with mocked_profile() as (ctx, operations):
            with self.assertRaisesRegex(Failure, "^simplex_event_schema$"):
                sender.handoff(ctx, event_id, payload(rule, output))
            self.assert_no_profile_work(ctx, operations)

    @PROFILE
    @given(event_id=EVENT, rule=TEXT, character=st.sampled_from(("a", "é", "Ж", "界", "🙂")))
    def test_utf8_over_budget_message_never_acquires_profile_lock(self, event_id, rule, character):
        event = payload(rule, "")
        _, empty_text, _ = message(event_id, event)
        available = 4096 - len(empty_text.encode())
        event["output"] = character * (available // len(character.encode()) + 1)
        _, text, _ = message(event_id, event)
        self.assertGreater(len(text.encode()), 4096)
        with mocked_profile() as (ctx, operations):
            with self.assertRaisesRegex(Failure, "^simplex_message_limit$"):
                sender.handoff(ctx, event_id, event)
            operations.configuration.assert_called_once_with(ctx)
            operations.lock.assert_not_called()
            operations.lookup.assert_not_called()
            operations.load.assert_not_called()
            operations.save.assert_not_called()
            ctx.run.assert_not_called()

    @PROFILE
    @given(event_id=EVENT, rule=TEXT, character=st.sampled_from(("a", "é", "Ж", "界", "🙂")))
    def test_exact_utf8_budget_preserves_native_receipt_binding(self, event_id, rule, character):
        event = payload(rule, "")
        _, empty_text, _ = message(event_id, event)
        available = 4096 - len(empty_text.encode())
        count, remainder = divmod(available, len(character.encode()))
        event["output"] = character * count + "a" * remainder
        key, text, body = message(event_id, event)
        self.assertEqual(len(text.encode()), 4096)
        with mocked_profile() as (ctx, operations):
            self.assertEqual(sender.handoff(ctx, event_id, event), 17)
            operations.lookup.assert_called_once()
            self.assertEqual(operations.lookup.call_args.args[1:3], ("[yggctl:" + key + "]", text))
            operations.save.assert_called_once_with(
                ctx,
                {
                    key: {
                        "body": body,
                        "binding": BINDING,
                        "status": "native-recorded",
                        "item_id": 17,
                    }
                },
            )
            ctx.run.assert_not_called()

    @PROFILE
    @given(event_id=EVENT, rule=TEXT, output=TEXT, item_id=st.integers(min_value=1, max_value=10**9))
    def test_durable_matching_receipt_is_reused_without_send(self, event_id, rule, output, item_id):
        event = payload(rule, output)
        key, _, body = message(event_id, event)
        journal = {
            key: {"body": body, "binding": BINDING, "status": "native-recorded", "item_id": item_id}
        }
        with mocked_profile(journal=journal, item=None) as (ctx, operations):
            self.assertEqual(sender.handoff(ctx, event_id, event), item_id)
            operations.save.assert_not_called()
            ctx.run.assert_not_called()

    @PROFILE
    @given(event_id=EVENT, rule=TEXT, output=TEXT)
    def test_ambiguous_attempt_is_not_automatically_retried(self, event_id, rule, output):
        event = payload(rule, output)
        key, _, body = message(event_id, event)
        journal = {
            key: {"body": body, "binding": BINDING, "status": "attempted", "item_id": None}
        }
        with mocked_profile(journal=journal, item=None) as (ctx, operations):
            with self.assertRaisesRegex(Failure, "^simplex_attempt_ambiguous_no_auto_retry$"):
                sender.handoff(ctx, event_id, event)
            operations.save.assert_not_called()
            ctx.run.assert_not_called()

    @PROFILE
    @given(event_id=EVENT, rule=TEXT, output=TEXT, field=st.sampled_from(("body", "binding")))
    def test_conflicting_attempt_binding_never_sends_or_checkpoints(
        self, event_id, rule, output, field
    ):
        event = payload(rule, output)
        key, _, body = message(event_id, event)
        row = {"body": body, "binding": BINDING, "status": "attempted", "item_id": None}
        value = body if field == "body" else BINDING
        row[field] = ("0" if value[0] != "0" else "1") + value[1:]
        with mocked_profile(journal={key: row}, item=None) as (ctx, operations):
            with self.assertRaisesRegex(Failure, "^simplex_attempt_binding_conflict$"):
                sender.handoff(ctx, event_id, event)
            operations.save.assert_not_called()
            ctx.run.assert_not_called()
