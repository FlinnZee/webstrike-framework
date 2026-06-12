#!/usr/bin/env python3
"""WebStrike entry point — Automated Web Pentesting Framework, created by NiMAA.

Usage:
    ./webstrike.py scan example.com
    ./webstrike.py modules
    ./webstrike.py check
"""
import sys
from pathlib import Path

# allow running from anywhere without installing
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wstrike.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
