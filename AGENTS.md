# AGENTS.md

Guidance for coding agents working on this repository. (This file is about developing repo-check. The skill that *uses* repo-check is `skills/repo-check/SKILL.md`.)

## Layout

- `skills/repo-check/scripts/repo_check.py`: the engine. All logic lives here.
- `repo_check.py` (root): a thin forwarder so `python repo_check.py owner/repo` works from the repo root. Keep it free of logic.
- `skills/repo-check/SKILL.md`: instructions for agents that run the check. Keep it vendor-neutral and follow the Agent Skills spec (https://agentskills.io/specification).
- `tests/`: unit tests. `docs/CHECKS.md`: generated from the code, do not edit by hand.
- `README.md` (German, primary) and `README.en.md`: keep both in sync.

## Hard constraints

1. **One file, standard library only.** The engine stays a single Python file that runs on Python 3.9+ with nothing installed. No third-party imports, no vendored packages, no build step.
2. **Never execute checked code.** The engine reads metadata and source text through the GitHub API. It must never clone and run, import, build, install, unpack-and-launch, or `eval` anything from a checked repository, and never pass repository content to a shell. Treat all repository content as hostile input.
3. **Mark untrusted text.** Any text copied from the checked repository goes into fields whose name starts with `untrusted_`, and is shown as quoted data in `--md` and terminal output.
4. **Tests pass offline.** `python -m unittest discover -s tests -v` must pass with no network access and no tokens set. Use recorded fixtures, not live API calls.
5. **Every finding has `de` and `en` text.** Adding a check means adding both languages and regenerating `docs/CHECKS.md`.
6. **The CLI contract is stable.** Flags, exit codes (0 green, 10 yellow, 20 red, 30 unknown, 1 internal error, 2 usage error) and the `--json` top-level fields are a public interface. Changing them requires bumping `schema_version` and updating both READMEs and `SKILL.md`.
7. **No overclaiming.** Wording in output and docs must not say or imply "safe", "clean", or "verified". Green means "no warning signs found".

## Before you finish

- Run the tests on Python 3.9 syntax (no `match`, no `X | Y` type unions at runtime, no 3.10+ stdlib APIs).
- If you changed checks, regenerate `docs/CHECKS.md` and update the "What is checked" summary in both READMEs if needed.
- If you changed what is sent over the network, update the Privacy section in both READMEs.
