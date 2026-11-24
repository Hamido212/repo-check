"""Regenerate docs/CHECKS.md from the engine:  python tests/generate_checks_md.py
The unit tests fail when docs/CHECKS.md and the engine disagree."""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "docs", "CHECKS.md")


def load_engine():
    spec = importlib.util.spec_from_file_location("repo_check", os.path.join(ROOT, "skills", "repo-check", "scripts", "repo_check.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["repo_check"] = mod        # dataclasses look the module up while it executes
    spec.loader.exec_module(mod)
    return mod


def build() -> str:
    rc = load_engine()
    return ("# repo-check: checks / Prüfungen\n\n"
            "_Generated from the engine by `python tests/generate_checks_md.py`. Do not edit by hand; "
            "`python repo_check.py --list-checks --lang en|de` prints the same tables._\n\n"
            "# English\n\n" + rc.list_checks("en") + "\n# Deutsch\n\n" + rc.list_checks("de"))


if __name__ == "__main__":
    os.makedirs(os.path.dirname(TARGET), exist_ok=True)
    with open(TARGET, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(build())
    print("wrote", TARGET)
