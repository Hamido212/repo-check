# Contributing

Thanks for helping. Issues and pull requests in German or English are welcome.

**Reporting a wrong verdict or a bug:** see [SECURITY.md](SECURITY.md) for false negatives, false positives, and vulnerabilities.

**Pull requests:**

1. Read [AGENTS.md](AGENTS.md). Its constraints apply to humans too: one Python file, standard library only, Python 3.9+, never execute code from a checked repository.
2. A new or changed check needs a test (offline, using fixtures), finding text in both `de` and `en`, and a regenerated `docs/CHECKS.md`.
3. Run the tests: `python -m unittest discover -s tests -v`
4. Keep wording sober. Output and docs never call a repository "safe"; green means "no warning signs found".

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
