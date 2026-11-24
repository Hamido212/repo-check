# Security policy

*Deutsch weiter unten.*

## Vulnerabilities in repo-check itself

Examples: a checked repository can make repo-check execute code, write files outside its temp area, leak a token, or manipulate the verdict through crafted content.

Please **do not open a public issue**. Report it privately via GitHub's private vulnerability reporting:
https://github.com/Hamido212/repo-check/security/advisories/new

Include the repo-check version (`python repo_check.py --version`), the steps or a minimal repository that reproduces it, and the impact you expect. You will get an answer as soon as possible; this is a one-person project, so please allow a few days.

Only the latest release is supported.

## Wrong verdicts (false negatives and false positives)

A wrong verdict is not a vulnerability in the tool. Open a normal issue:

- **Missed warning sign (false negative):** a repository rated green or yellow that you have good reason to believe is malicious. Give the repository, the repo-check version, and what you found (for example a VirusTotal link). Do not attach malware samples or post direct download links to them.
- **False alarm (false positive):** a finding that is wrong or misleading. Give the repository, the finding `id` from `--json`, and why you think it is wrong.

If a missed detection is part of an active campaign and public discussion would help the attacker, use the private reporting link above instead.

---

## Deutsch

**Sicherheitslücke in repo-check selbst** (zum Beispiel: ein geprüftes Repository kann repo-check dazu bringen, Code auszuführen, einen Token preiszugeben oder die Ampel zu manipulieren): bitte nicht öffentlich melden, sondern privat über
https://github.com/Hamido212/repo-check/security/advisories/new

**Falsche Ampel** (Schadsoftware übersehen oder Fehlalarm): normales Issue öffnen, mit Repository, Version von repo-check und Begründung. Bei einem Fehlalarm bitte die `id` des Fundes aus `--json` angeben. Keine Schadsoftware-Dateien anhängen.
