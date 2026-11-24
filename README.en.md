[Deutsch](README.md) · **English**

# repo-check

A check before you download a program from GitHub. You give it a GitHub link and get a traffic light with reasons: Is this really the original project? Can the downloads be traced back to it? Are there warning signs of malware?

```
python repo_check.py owner/repo
```

> **Green means "no warning signs found", not "safe".**
> repo-check looks at the repository (the project's page and files on GitHub) and at the metadata of its downloads. It cannot prove what a downloaded file actually does on your computer.

## What it is and what it is not

**It is** a single Python script with no extra packages. It asks GitHub for information about the project and searches the source code for typical traits of malware. It never runs anything from the checked project.

**It is not** a virus scanner, a guarantee, or a substitute for caution. The check mostly judges the packaging: the account, the project's age, the download metadata, and the readable source code. It never opens the finished program file you would actually run. Someone who uses an older account and hides the malware only in that file can get green.

## Quickstart

### Windows

1. **Install Python.** Download it from [python.org/downloads](https://www.python.org/downloads/) and run the installer. In the first window, tick **"Add python.exe to PATH"** at the bottom.
2. **Download repo-check.** On [github.com/Hamido212/repo-check](https://github.com/Hamido212/repo-check), click the green **Code** button, then **Download ZIP**. Unzip it (right-click → "Extract All").
3. **Open a terminal.** Open the unzipped folder, right-click an empty spot and choose **"Open in Terminal"**.
4. **Check.** Type this and press Enter (replace the link with the project you want to check):

   ```
   python repo_check.py https://github.com/owner/repo
   ```

   If Windows opens the Microsoft Store instead or says Python was not found, use `py` instead of `python`.

A check usually takes 20 to 30 seconds, up to two minutes for very large projects.

### macOS and Linux

Run `python3 --version` to see whether Python 3.9 or newer is installed (otherwise install it from [python.org](https://www.python.org/downloads/)). Then download (or use the ZIP as above) and run:

```
git clone https://github.com/Hamido212/repo-check.git
cd repo-check
python3 repo_check.py owner/repo
```

### Useful options

| Option | Effect |
|---|---|
| `--lang de` / `--lang en` | Output language |
| `--md` / `--json` | Report as Markdown (to paste into a chat) or JSON (for programs) |
| `--no-code`, `--no-stars`, `--no-vt`, `--no-trivy`, `--no-scorecard` | Skip individual parts |
| `--list-checks` | List every individual check |
| `--version` | Show the version |

## Reading the result

| Light | Meaning |
|---|---|
| 🟢 **green** | No warning signs found. Not proof that the program is harmless. |
| 🟡 **yellow** | There are warning signs, for example a brand-new project with a suspicious number of stars, or a lure topic such as "crack" on a project nobody uses. Read the reasons and decide. |
| 🔴 **red** | Clear warning signs, for example an account imitating a well-known project, or malware reports. Do not download until this is resolved. |
| ⚪ **unknown** | The check could not be completed: the repository does not exist, GitHub was unreachable, the request limit was hit, or the project could not be scanned completely. The report names the reason and what to do. |

Below the light you get:

- **Reasons:** what led to the rating.
- **Capabilities:** what the program can do according to its source code, similar to app permissions on a phone (for example "starts automatically with Windows" or "reads browser data"). This is not an accusation. The question is whether it fits the program's purpose.
- **Trust signals:** what speaks for the project, for example an attested automated build. They never offset a warning sign.
- **Caveats:** short sentences you can pass on, for example "The project is only 17 days old".
- **Not checked:** what was skipped or did not work.

```text
repo-check 1.0.0 · yt-dlp/yt-dlp · 2026-11-24 20:17
stars 210,417 · forks 18,628 · contributors 301+ · license Unlicense · created 2020-10-26

🟢 GREEN: no warning signs found
8 checks found only minor points, nothing that adds up to a warning. That is not a guarantee: see the limits.

Warning signs
  🔸 Connects directly to a public IP address instead of a domain name.
     Sometimes harmless, sometimes a hidden server. Found in 2 places.
     › yt_dlp/extractor/presstv.py:34

What the program can do
  • Reads saved browser data, passwords, wallets or login tokens. Fine when it is the tool's job
    (e.g. a downloader using your cookies), but know that it can.

Trust signals
  ✓ Established project: 6 years old, 301+ contributors.
  ✓ The release is immutable: its files can't be swapped afterwards.
  ✓ Build provenance is attested for 4 file(s).
  ✓ All files were uploaded by GitHub Actions (automated build).
  […]

Worth saying out loud
  • It can read browser cookies or saved logins; that's part of how it works, but you should know.

Limits
  This checks the repository and its release metadata. It does not prove what a downloaded file does on your computer.
  Green means no warning signs were found, not that the project is safe. New or well-hidden malware can pass.
```

The example is shortened. The full report also has notes, skipped checks, VirusTotal links and issues to read.

For scripts: the exit code (the number a program returns when it ends) is `0` green, `10` yellow, `20` red, `30` unknown, `1` internal error, `2` usage error.

## As a skill in your AI agent

A skill is a folder with instructions (`SKILL.md`) that an AI coding agent loads by itself when a question matches. The agent then runs the script, reads suspicious code locations, and explains the result. You still need Python on your computer.

Afterwards, just ask: "Is github.com/owner/repo safe?"

**For many agents at once** (needs [Node.js](https://nodejs.org)): the [`skills`](https://github.com/vercel-labs/skills) tool asks which agents to install for. `-g` means: for all your projects.

```
npx skills add Hamido212/repo-check -g
```

**Claude Code**

```
npx skills add Hamido212/repo-check -g -a claude-code
```

Or as a plugin with automatic updates, typed inside Claude Code:

```
/plugin marketplace add Hamido212/repo-check
/plugin install repo-check@hyos
```

By hand: copy the folder `skills/repo-check` to `~/.claude/skills/repo-check` (`~` is your user folder, on Windows `C:\Users\<name>`).

**OpenAI Codex**

```
npx skills add Hamido212/repo-check -g -a codex
```

By hand: copy `skills/repo-check` to `~/.agents/skills/repo-check`. Invoke it in Codex with `$repo-check`, or let Codex pick it.

**Gemini CLI**

```
gemini skills install https://github.com/Hamido212/repo-check.git --path skills/repo-check
```

**GitHub Copilot** (Copilot CLI and agent mode in the editor; needs GitHub CLI 2.90 or newer, feature in preview)

```
gh skill install Hamido212/repo-check repo-check --agent github-copilot --scope user
```

**Cursor**

```
npx skills add Hamido212/repo-check -g -a cursor
```

**OpenCode**

```
npx skills add Hamido212/repo-check -g -a opencode
```

**Other agents** (for example Amp, Cline, Antigravity, Kiro, Goose): `npx skills add Hamido212/repo-check -g -a <agent>`. Names are in the [agent list](https://github.com/vercel-labs/skills/blob/main/docs/agents.md).

**ChatGPT, the Gemini app, Claude on the web:** these chat assistants cannot run the script on your computer. Run the check yourself (`--md`) and paste the report into the chat together with [this prompt](prompts/chat-assistant.md).

## What is checked

- **Origin:** age of the account and the project, fork (copy of another project), renamed project, imitation of a better-known project.
- **Lures:** topics such as cracks, cheats or "premium for free", password-protected archives, download buttons that lead away from GitHub.
- **Stars:** do the stars match real usage (forks, issues, contributions)? Bought stars are a known trick.
- **Releases** (published downloads): checksums (a kind of fingerprint of a file), signatures, build provenance attestations, who uploaded the files, and whether a file was replaced afterwards.
- **VirusTotal** (optional): looks up the file fingerprints in known results.
- **Source code:** searches for typical malware patterns, such as hidden or encrypted code, access to passwords combined with a channel to the outside, invisible characters, and text meant to steer AI assistants.
- **Issues:** reports by other users about viruses or malware.
- **OpenSSF Scorecard** and **Trivy** (optional): public security rating and vulnerability scan.

The full list of individual checks is in [docs/CHECKS.md](docs/CHECKS.md).

## Optional: GitHub token, VirusTotal, Trivy

**GitHub token.** Without signing in, GitHub allows only a few requests per hour. That is enough for about six checks per hour. If the [GitHub CLI](https://cli.github.com) is installed and you signed in with `gh auth login`, repo-check uses it automatically. Otherwise you can put a token (a password just for programs) in `GITHUB_TOKEN`. For public repositories it needs no permissions.

**VirusTotal.** Create a free account on [virustotal.com](https://www.virustotal.com) and copy the API key from your profile. Then:

- Windows: `setx VT_API_KEY "your-key"`, then open a new terminal.
- macOS/Linux: `export VT_API_KEY="your-key"` (add it to `~/.zshrc` or `~/.bashrc` to keep it).

The free quota is small. Nothing is uploaded; see Privacy.

**Trivy.** Install [Trivy](https://trivy.dev) following the official instructions. If it is not on your PATH, set `TRIVY_PATH` to its location.

Other environment variables: `REPO_CHECK_LANG` (default language), `NO_COLOR` (no colors).

## Privacy

What leaves your computer:

- **Requests to GitHub** (`api.github.com`, and `codeload.github.com` for the source code) about the repository you name: project data, account, releases, issues, source code. Plus one search for projects with a similar name, to detect copies. With a token, GitHub sees which account is asking.
- **VirusTotal** (`www.virustotal.com`): only if `VT_API_KEY` is set, and only the checksums (fingerprints) of at most three release files. No files are uploaded.
- **OpenSSF Scorecard** (`api.securityscorecards.dev`): one lookup of the public rating for the repository, unless you pass `--no-scorecard`.

Nothing else: no analytics, no account, no server of ours. Trivy runs locally, but it fetches the repository and its vulnerability database itself. If no token is set, repo-check asks the GitHub CLI on your machine for your login (`gh auth token`); the token is sent only to `api.github.com`.

## FAQ

**Green does not mean safe. What does it mean?**
Green means "no warning signs found". The check sees the repository and the download metadata, not what a program does on your computer. Run unknown Windows programs in an isolated environment such as [Windows Sandbox](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/) first (Windows Pro and up, not Windows Home).

**Why does a well-known tool get yellow?**
Yellow does not mean "malware", it means "read the reasons". Typical cases for legitimate projects: the project is only a few weeks old; the source tree contains a finished program file nobody can verify; or a few antivirus engines on VirusTotal flag an unsigned file, which is often a false alarm but cannot be settled from the outside.

**Does it run anything from the checked project?**
No. repo-check only reads. It never downloads programs to start them.

**Does it work with GitLab or other sites?**
No, GitHub only.

**Can I discuss the result with an AI?**
Yes: run `python repo_check.py owner/repo --md` and paste the report into your chat with [this prompt](prompts/chat-assistant.md).

## Contributing

Bugs, false warnings, or missed malware: see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Please do not report security vulnerabilities in the tool itself publicly; use GitHub's private reporting.

## License

[MIT](LICENSE) © 2026 Hamid Yosefsei (HYOS)
