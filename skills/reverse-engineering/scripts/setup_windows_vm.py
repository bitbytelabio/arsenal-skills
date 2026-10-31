#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""Windows VM Ansible Provisioning & Tool Catalog Manager (Compatibility Wrapper).

Delegates to setup_vm.py with --os windows defaults.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add script dir to sys.path and import setup_vm
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import setup_vm  # noqa: E402


def main() -> int:
    return setup_vm.main()


if __name__ == "__main__":
    sys.exit(main())
