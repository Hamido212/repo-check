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

**It is not** a virus scanner, a guarantee, or a substitute for caution. Well-hidden malware can pass every check. And many harmless small projects get yellow, for example because their downloads are not digitally signed.

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
| 🟡 **yellow** | Something is unusual or missing, for example no checksums for the downloads. Read the reasons and decide. |
| 🔴 **red** | Clear warning signs, for example an account imitating a well-known project, or malware reports. Do not download until this is resolved. |
| ⚪ **unknown** | The check could not be completed, for example because the repository does not exist or GitHub was unreachable. |

Below the light you get:

- **Reasons:** what led to the rating.
- **Capabilities:** what the program can do according to its source code, similar to app permissions on a phone (for example "starts automatically with Windows" or "reads browser data"). This is not an accusation. The question is whether it fits the program's purpose.
- **Caveats:** short sentences you can pass on, for example "Not signed; Windows will warn on first start".
- **Not checked:** what was skipped or did not work.

<!-- EXAMPLE-OUTPUT: filled in after the engine is final -->

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

- **Origin:** account age, fork (copy of another project), renamed project, imitation of a better-known project.
- **Stars:** do the stars match real usage (forks, issues, contributions)? Bought stars are a known trick.
- **Releases** (published downloads): checksums (a kind of fingerprint of a file), signatures, build provenance attestations, and who uploaded the files.
- **VirusTotal** (optional): looks up the file fingerprints in known results.
- **Source code:** searches for typical malware patterns, such as hidden code or access to passwords.
- **Issues:** reports by other users about viruses or malware.
- **OpenSSF Scorecard** and **Trivy** (optional): public security rating and vulnerability scan.

The full list of individual checks is in [docs/CHECKS.md](docs/CHECKS.md).

## Optional: GitHub token, VirusTotal, Trivy

**GitHub token.** Without signing in, GitHub allows only a few requests per hour. If the [GitHub CLI](https://cli.github.com) is installed and you signed in with `gh auth login`, repo-check uses it automatically. Otherwise you can put a token (a password just for programs) in `GITHUB_TOKEN`. For public repositories it needs no permissions.

**VirusTotal.** Create a free account on [virustotal.com](https://www.virustotal.com) and copy the API key from your profile. Then:

- Windows: `setx VT_API_KEY "your-key"`, then open a new terminal.
- macOS/Linux: `export VT_API_KEY="your-key"` (add it to `~/.zshrc` or `~/.bashrc` to keep it).

The free quota is small. Nothing is uploaded; see Privacy.

**Trivy.** Install [Trivy](https://trivy.dev) following the official instructions. If it is not on your PATH, set `TRIVY_PATH` to its location.

Other environment variables: `REPO_CHECK_LANG` (default language), `NO_COLOR` (no colors).

## Privacy

What leaves your computer:

- **Requests to the GitHub API** about the repository you name (project data, releases, issues, source code). With a token, GitHub sees which account is asking.
- **VirusTotal:** only if `VT_API_KEY` is set, and only the checksums (fingerprints) of the release files. No files are uploaded.
- **OpenSSF Scorecard:** one lookup of the public rating for the repository, unless you pass `--no-scorecard`.

Nothing else: no analytics, no account, no server of ours. Trivy runs locally, but it downloads its own vulnerability database.

## FAQ

**Green does not mean safe. What does it mean?**
Green means "no warning signs found". The check sees the repository and the download metadata, not what a program does on your computer. Run unknown Windows programs in an isolated environment such as [Windows Sandbox](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/) first (Windows Pro and up, not Windows Home).

**Why does a well-known tool get yellow?**
Many small open-source projects do not sign their downloads or publish checksums. That is not evidence of malware, but it makes it harder to verify that a file is genuine.

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
