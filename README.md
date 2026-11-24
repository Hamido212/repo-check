**Deutsch** · [English](README.en.md)

# repo-check

Ein Check, bevor du ein Programm von GitHub herunterlädst. Du gibst einen GitHub-Link ein und bekommst eine Ampel mit Begründung: Ist das wirklich das Original? Sind die Downloads nachvollziehbar? Gibt es Warnzeichen für Schadsoftware?

```
python repo_check.py owner/repo
```

> **Grün heißt „keine Warnzeichen gefunden“, nicht „sicher“.**
> repo-check schaut sich das Repository (den Projektordner auf GitHub) und die Angaben zu den Downloads an. Was eine heruntergeladene Datei auf deinem Rechner tatsächlich tut, kann es nicht beweisen.

## Was es ist und was nicht

**Es ist** ein einzelnes Python-Skript ohne Zusatzpakete. Es fragt GitHub nach Informationen zum Projekt und durchsucht den Quellcode nach typischen Merkmalen von Schadsoftware. Es führt nie etwas aus dem geprüften Projekt aus.

**Es ist kein** Virenscanner, keine Garantie und kein Ersatz für Vorsicht. Ein geschickt verstecktes Schadprogramm kann alle Prüfungen bestehen. Umgekehrt bekommen viele harmlose kleine Projekte Gelb, weil ihnen zum Beispiel eine digitale Signatur fehlt.

## Schnellstart

### Windows

1. **Python installieren.** Lade Python von [python.org/downloads](https://www.python.org/downloads/) und starte den Installer. Setz unten im ersten Fenster den Haken bei **„Add python.exe to PATH“**.
2. **repo-check herunterladen.** Auf [github.com/Hamido212/repo-check](https://github.com/Hamido212/repo-check) auf den grünen Knopf **Code** klicken, dann **Download ZIP**. Die ZIP-Datei entpacken (Rechtsklick → „Alle extrahieren“).
3. **Terminal öffnen.** Den entpackten Ordner öffnen, mit der rechten Maustaste in eine leere Stelle klicken und **„Im Terminal öffnen“** wählen.
4. **Prüfen.** Eintippen und Enter drücken (statt `owner/repo` den Link oder Namen des Projekts, das du prüfen willst):

   ```
   python repo_check.py https://github.com/owner/repo
   ```

   Falls Windows stattdessen den Microsoft Store öffnet oder „Python wurde nicht gefunden“ meldet, nimm `py` statt `python`.

### macOS und Linux

Prüf mit `python3 --version`, ob Python 3.9 oder neuer da ist (sonst von [python.org](https://www.python.org/downloads/) installieren). Dann herunterladen (oder ZIP wie oben) und starten:

```
git clone https://github.com/Hamido212/repo-check.git
cd repo-check
python3 repo_check.py owner/repo
```

### Nützliche Optionen

| Option | Wirkung |
|---|---|
| `--lang de` / `--lang en` | Sprache der Ausgabe |
| `--md` / `--json` | Bericht als Markdown (zum Einfügen in einen Chat) oder als JSON (für Programme) |
| `--no-code`, `--no-stars`, `--no-vt`, `--no-trivy`, `--no-scorecard` | Einzelne Teile auslassen |
| `--list-checks` | Alle Einzelprüfungen anzeigen |
| `--version` | Version anzeigen |

## Das Ergebnis lesen

| Ampel | Bedeutung |
|---|---|
| 🟢 **grün** | Keine Warnzeichen gefunden. Kein Beweis, dass das Programm harmlos ist. |
| 🟡 **gelb** | Etwas ist ungewöhnlich oder fehlt, zum Beispiel keine Prüfsummen für die Downloads. Lies die Gründe und entscheide selbst. |
| 🔴 **rot** | Deutliche Warnzeichen, zum Beispiel ein Konto, das sich als bekanntes Projekt ausgibt, oder Malware-Meldungen. Nicht herunterladen, bevor das geklärt ist. |
| ⚪ **unbekannt** | Die Prüfung konnte nicht abgeschlossen werden, etwa weil das Repository nicht existiert oder GitHub nicht erreichbar war. |

Unter der Ampel stehen:

- **Gründe:** was zur Einstufung geführt hat.
- **Fähigkeiten:** was das Programm laut Quellcode tun kann, ähnlich wie App-Berechtigungen auf dem Handy (zum Beispiel „startet automatisch mit Windows“ oder „liest Browserdaten“). Das ist kein Vorwurf. Die Frage ist, ob es zum Zweck des Programms passt.
- **Hinweise:** kurze Sätze, die du weitergeben kannst, zum Beispiel „Nicht signiert, Windows warnt beim Start“.
- **Nicht geprüft:** was ausgelassen wurde oder nicht ging.

<!-- EXAMPLE-OUTPUT: filled in after the engine is final -->

Für eigene Skripte: Der Exit-Code (die Zahl, die ein Programm beim Beenden zurückgibt) ist `0` grün, `10` gelb, `20` rot, `30` unbekannt, `1` interner Fehler, `2` falscher Aufruf.

## Als Skill in deinem KI-Agenten

Ein Skill ist ein Ordner mit Anleitung (`SKILL.md`), den ein KI-Coding-Agent bei passenden Fragen selbst lädt. Der Agent führt dann das Skript aus, liest auffällige Code-Stellen nach und erklärt dir das Ergebnis. Du brauchst trotzdem Python auf dem Rechner.

Danach fragst du einfach: „Ist github.com/owner/repo sicher?“

**Für viele Agenten auf einmal** (braucht [Node.js](https://nodejs.org)): Das Werkzeug [`skills`](https://github.com/vercel-labs/skills) fragt, für welche Agenten du installieren willst. `-g` heißt: für alle deine Projekte.

```
npx skills add Hamido212/repo-check -g
```

**Claude Code**

```
npx skills add Hamido212/repo-check -g -a claude-code
```

Oder als Plugin mit automatischen Updates, in Claude Code eingeben:

```
/plugin marketplace add Hamido212/repo-check
/plugin install repo-check@hyos
```

Von Hand: den Ordner `skills/repo-check` nach `~/.claude/skills/repo-check` kopieren (`~` ist dein Benutzerordner, unter Windows `C:\Users\<Name>`).

**OpenAI Codex**

```
npx skills add Hamido212/repo-check -g -a codex
```

Von Hand: `skills/repo-check` nach `~/.agents/skills/repo-check` kopieren. Aufruf in Codex mit `$repo-check` oder automatisch.

**Gemini CLI**

```
gemini skills install https://github.com/Hamido212/repo-check.git --path skills/repo-check
```

**GitHub Copilot** (Copilot CLI und Agent-Modus im Editor; braucht GitHub CLI 2.90 oder neuer, Funktion in der Vorschau)

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

**Andere Agenten** (zum Beispiel Amp, Cline, Antigravity, Kiro, Goose): `npx skills add Hamido212/repo-check -g -a <agent>`. Die Namen stehen in der [Agentenliste](https://github.com/vercel-labs/skills/blob/main/docs/agents.md).

**ChatGPT, Gemini-App, Claude im Browser:** Diese Chat-Assistenten können das Skript auf deinem Rechner nicht ausführen. Lass den Check selbst laufen (`--md`) und füg den Bericht zusammen mit [diesem Prompt](prompts/chat-assistant.md) in den Chat ein.

## Was geprüft wird

- **Herkunft:** Alter des Kontos, Fork (Kopie eines anderen Projekts), umbenanntes Projekt, Nachahmung eines bekannteren Projekts.
- **Sterne:** Passen die Sterne zur echten Nutzung (Forks, Issues, Beiträge)? Gekaufte Sterne sind ein bekannter Trick.
- **Releases** (veröffentlichte Downloads): Prüfsummen (eine Art Fingerabdruck einer Datei), Signaturen, Herkunftsnachweise des Builds (build provenance) und wer die Dateien hochgeladen hat.
- **VirusTotal** (optional): Abgleich der Datei-Fingerabdrücke mit bekannten Ergebnissen.
- **Quellcode:** Suche nach typischen Mustern von Schadsoftware, etwa versteckter Code oder Zugriff auf Passwörter.
- **Issues:** Meldungen anderer Nutzer zu Viren oder Malware.
- **OpenSSF Scorecard** und **Trivy** (optional): öffentliche Sicherheitsbewertung und Schwachstellen-Scan.

Die vollständige Liste aller Einzelprüfungen steht in [docs/CHECKS.md](docs/CHECKS.md).

## Optional: GitHub-Token, VirusTotal, Trivy

**GitHub-Token.** Ohne Anmeldung erlaubt GitHub nur wenige Anfragen pro Stunde. Wenn du die [GitHub CLI](https://cli.github.com) installiert und mit `gh auth login` angemeldet bist, nutzt repo-check das automatisch. Sonst kannst du einen Token (eine Art Passwort nur für Programme) in `GITHUB_TOKEN` hinterlegen. Für öffentliche Repositories braucht er keine Berechtigungen.

**VirusTotal.** Leg ein kostenloses Konto auf [virustotal.com](https://www.virustotal.com) an und kopier den API-Schlüssel aus deinem Profil. Dann:

- Windows: `setx VT_API_KEY "dein-schlüssel"` und danach ein neues Terminal öffnen.
- macOS/Linux: `export VT_API_KEY="dein-schlüssel"` (für dauerhaft in `~/.zshrc` oder `~/.bashrc` eintragen).

Das kostenlose Kontingent ist klein. Hochgeladen wird nichts, siehe Datenschutz.

**Trivy.** Installier [Trivy](https://trivy.dev) nach der offiziellen Anleitung. Liegt es nicht im Suchpfad, gib den Ort in `TRIVY_PATH` an.

Weitere Umgebungsvariablen: `REPO_CHECK_LANG` (Standardsprache), `NO_COLOR` (keine Farben).

## Datenschutz

Was deinen Rechner verlässt:

- **Anfragen an die GitHub-API** zum Repository, das du nennst (Projektdaten, Releases, Issues, Quellcode). Mit Token sieht GitHub, welches Konto fragt.
- **VirusTotal:** nur wenn `VT_API_KEY` gesetzt ist, und nur die Prüfsummen (Fingerabdrücke) der Release-Dateien. Es werden keine Dateien hochgeladen.
- **OpenSSF Scorecard:** eine Abfrage der öffentlichen Bewertung für das Repository, außer mit `--no-scorecard`.

Sonst nichts: keine Statistik, kein Konto, kein Server von uns. Trivy läuft lokal; es lädt aber selbst seine Schwachstellen-Datenbank herunter.

## Häufige Fragen

**Grün heißt nicht sicher. Was heißt es dann?**
Grün heißt „keine Warnzeichen gefunden“. Der Check sieht das Repository und die Angaben zu den Downloads, nicht das, was ein Programm auf deinem Rechner tut. Starte unbekannte Windows-Programme zuerst in einer abgeschotteten Umgebung wie der [Windows-Sandbox](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/) (ab Windows Pro, nicht in Windows Home).

**Warum bekommt ein bekanntes Tool Gelb?**
Viele kleine Open-Source-Projekte signieren ihre Downloads nicht und veröffentlichen keine Prüfsummen. Das ist kein Beweis für Schadsoftware, macht es aber schwerer nachzuprüfen, dass die Datei echt ist.

**Wird etwas aus dem geprüften Projekt ausgeführt?**
Nein. repo-check liest nur. Es lädt keine Programme herunter, um sie zu starten.

**Geht das auch mit GitLab oder anderen Seiten?**
Nein, nur GitHub.

**Kann ich das Ergebnis mit einer KI besprechen?**
Ja: `python repo_check.py owner/repo --md` ausführen und den Bericht mit [diesem Prompt](prompts/chat-assistant.md) in deinen Chat einfügen.

## Mitmachen

Fehler, falsche Warnungen oder übersehene Schadsoftware: siehe [CONTRIBUTING.md](CONTRIBUTING.md) und [SECURITY.md](SECURITY.md). Sicherheitslücken im Tool selbst bitte nicht öffentlich melden, sondern über die private Meldung auf GitHub.

## Lizenz

[MIT](LICENSE) © 2026 Hamid Yosefsei (HYOS)
