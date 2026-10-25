"""Bounded CLI dispatch properties; every command handler and launcher is mocked."""

import argparse
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hypothesis import given, strategies as st

from core import Failure
from fuzz_support import OfflineFuzzCase, PROFILE
import main


TEXT = st.text(max_size=40)
COMMAND_NAMES = tuple(main.COMMANDS)
LIMITED_COMMANDS = tuple(name for name, spec in main.COMMANDS.items() if spec.most >= 0)
FLAG_ERRORS = {
    "apply": "apply_not_supported_here",
    "force": "force_only_for_add_peer",
    "full": "backup_options_only",
    "recipient": "backup_options_only",
}
FORBIDDEN_FLAGS = tuple(
    (name, flag)
    for name, spec in main.COMMANDS.items()
    for flag in FLAG_ERRORS
    if ("full" if flag == "recipient" else flag) not in spec.flags
)


def arguments(command, values=(), **flags):
    return argparse.Namespace(
        command=command,
        args=list(values),
        apply=flags.get("apply", False),
        force=flags.get("force", False),
        full=flags.get("full", False),
        recipient=flags.get("recipient"),
    )


def inert_context():
    return SimpleNamespace(
        p=object(),
        root=Mock(),
        run=Mock(side_effect=AssertionError("external execution forbidden in this fixture")),
        api=Mock(side_effect=AssertionError("admin calls forbidden in this fixture")),
    )


class CliFuzzProperties(OfflineFuzzCase):
    @PROFILE
    @given(command=st.sampled_from(COMMAND_NAMES), values=st.lists(TEXT, max_size=5))
    def test_dispatch_preserves_arguments_and_root_requirement(self, command, values):
        spec = main.COMMANDS[command]
        values = values if spec.most < 0 else values[: spec.most]
        args = arguments(command, values)
        ctx, handler = inert_context(), Mock()
        with (
            patch.dict(main.COMMANDS, {command: replace(spec, handler=handler)}),
            patch.object(main.sandbox, "inside", return_value=True),
            patch.object(main.sandbox, "run") as launcher,
        ):
            main.dispatch(ctx, args)
        handler.assert_called_once_with(ctx, args, args.args)
        self.assertEqual(ctx.root.call_count, int(spec.root))
        ctx.run.assert_not_called()
        ctx.api.assert_not_called()
        launcher.assert_not_called()

    @PROFILE
    @given(command=st.sampled_from(LIMITED_COMMANDS), extra=st.lists(TEXT, min_size=1, max_size=5))
    def test_surplus_arguments_never_reach_a_handler(self, command, extra):
        spec = main.COMMANDS[command]
        ctx, handler = inert_context(), Mock()
        args = arguments(command, ["synthetic"] * spec.most + extra)
        with (
            patch.dict(main.COMMANDS, {command: replace(spec, handler=handler)}),
            patch.object(main.sandbox, "run") as launcher,
            self.assertRaisesRegex(Failure, "^unexpected_arguments$"),
        ):
            main.dispatch(ctx, args)
        handler.assert_not_called()
        ctx.root.assert_not_called()
        ctx.run.assert_not_called()
        ctx.api.assert_not_called()
        launcher.assert_not_called()

    @PROFILE
    @given(case=st.sampled_from(FORBIDDEN_FLAGS), recipient=st.text(min_size=1, max_size=40))
    def test_unsupported_flags_fail_before_privilege_or_handler(self, case, recipient):
        command, flag = case
        spec = main.COMMANDS[command]
        ctx, handler = inert_context(), Mock()
        args = arguments(command, **{flag: recipient if flag == "recipient" else True})
        with (
            patch.dict(main.COMMANDS, {command: replace(spec, handler=handler)}),
            patch.object(main.sandbox, "run") as launcher,
            self.assertRaisesRegex(Failure, "^" + FLAG_ERRORS[flag] + "$"),
        ):
            main.dispatch(ctx, args)
        handler.assert_not_called()
        ctx.root.assert_not_called()
        ctx.run.assert_not_called()
        ctx.api.assert_not_called()
        launcher.assert_not_called()

    @PROFILE
    @given(suffix=TEXT, values=st.lists(TEXT, max_size=5))
    def test_unknown_commands_have_fixed_failure_and_no_effects(self, suffix, values):
        ctx = inert_context()
        with (
            patch.object(main.sandbox, "run") as launcher,
            self.assertRaisesRegex(Failure, "^unknown_command_use_help$"),
        ):
            main.dispatch(ctx, arguments("synthetic-unknown-" + suffix, values))
        ctx.root.assert_called_once_with()
        ctx.run.assert_not_called()
        ctx.api.assert_not_called()
        launcher.assert_not_called()
