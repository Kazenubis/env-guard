"""Allows `python -m env_guard ...`."""

import sys

from env_guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
