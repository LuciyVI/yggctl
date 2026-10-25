"""Docker entrypoint: ordinary Pytest arguments or a bounded plateau session."""

import os
import sys


def main():
    args = sys.argv[1:]
    if args[:1] == ["plateau"]:
        from fuzz_plateau import main as plateau_main

        return plateau_main(args[1:])
    os.execv(sys.executable, [sys.executable, "-B", "-m", "pytest", *args])


if __name__ == "__main__":
    raise SystemExit(main())
