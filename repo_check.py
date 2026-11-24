#!/usr/bin/env python3
"""Shim so `python repo_check.py owner/repo` works from the repository root.
The engine lives in skills/repo-check/scripts/repo_check.py."""
import os
import runpy

runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills", "repo-check", "scripts", "repo_check.py"),
               run_name="__main__")
