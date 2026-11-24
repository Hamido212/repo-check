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

**Es ist kein** Virenscanner, keine Garantie und kein Ersatz für Vorsicht. Der Check beurteilt vor allem das Drumherum: das Konto, das Alter des Projekts, die Angaben zu den Downloads und den lesbaren Quellcode. Die fertige Programmdatei, die du am Ende startest, öffnet er nie. Wer ein älteres Konto benutzt und die Schadsoftware nur in dieser Datei versteckt, kann Grün bekommen.

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

Ein Check dauert meist 20 bis 30 Sekunden, bei sehr großen Projekten bis zu zwei Minuten.

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
| 🟡 **gelb** | Es gibt Warnzeichen, zum Beispiel ein brandneues Projekt mit auffällig vielen Sternen oder ein Köder-Thema wie „Crack“ bei einem Projekt ohne Nutzer. Lies die Gründe und entscheide selbst. |
| 🔴 **rot** | Deutliche Warnzeichen, zum Beispiel ein Konto, das sich als bekanntes Projekt ausgibt, oder Malware-Meldungen. Nicht herunterladen, bevor das geklärt ist. |
| ⚪ **unbekannt** | Die Prüfung konnte nicht abgeschlossen werden: Das Repository existiert nicht, GitHub war nicht erreichbar, das Anfragelimit ist erreicht, oder das Projekt ließ sich nicht vollständig durchsuchen. Der Bericht nennt den Grund und was du tun kannst. |

Unter der Ampel stehen:

- **Gründe:** was zur Einstufung geführt hat.
- **Fähigkeiten:** was das Programm laut Quellcode tun kann, ähnlich wie App-Berechtigungen auf dem Handy (zum Beispiel „startet automatisch mit Windows“ oder „liest Browserdaten“). Das ist kein Vorwurf. Die Frage ist, ob es zum Zweck des Programms passt.
- **Vertrauenssignale:** was für das Projekt spricht, zum Beispiel ein belegter automatischer Build. Sie gleichen nie ein Warnzeichen aus.
- **Hinweise:** kurze Sätze, die du weitergeben kannst, zum Beispiel „Das Projekt ist erst 17 Tage alt“.
- **Nicht geprüft:** was ausgelassen wurde oder nicht ging.

```text
repo-check 1.0.0 · yt-dlp/yt-dlp · 2026-11-24 20:17
Sterne 210.417 · Forks 18.628 · Mitwirkende 301+ · Lizenz Unlicense · erstellt 26.10.2020

🟢 GRÜN: keine Warnzeichen gefunden
8 Prüfungen haben nur Kleinigkeiten gefunden, nichts, was eine Warnung ergibt. Das ist keine Garantie: siehe Grenzen.

Warnzeichen
  🔸 Verbindet sich direkt mit einer öffentlichen IP-Adresse statt einem Domainnamen.
     Manchmal harmlos, manchmal ein versteckter Server. An 2 Stellen gefunden.
     › yt_dlp/extractor/presstv.py:34

Was das Programm kann
  • Liest gespeicherte Browser-Daten, Passwörter, Wallets oder Login-Tokens. In Ordnung, wenn das
    die Aufgabe ist (z. B. ein Downloader mit deinen Cookies), aber du solltest es wissen.

Vertrauenssignale
  ✓ Etabliertes Projekt: 6 Jahre alt, 301+ Mitwirkende.
  ✓ Das Release ist unveränderlich: Die Dateien lassen sich nachträglich nicht austauschen.
  ✓ Die Build-Herkunft ist für 4 Datei(en) belegt (Attestation).
  ✓ Alle Dateien hat GitHub Actions hochgeladen (automatischer Build).
  […]

Das solltest du dazusagen
  • Es kann Browser-Cookies oder gespeicherte Logins lesen; das gehört zur Funktion, du solltest es aber wissen.

Grenzen
  Geprüft werden das Repo und die Release-Angaben. Was eine heruntergeladene Datei auf deinem Rechner tut, beweist das nicht.
  Grün heißt: keine Warnzeichen gefunden, nicht: sicher. Neue oder gut versteckte Schadsoftware kann durchrutschen.
```

Das Beispiel ist gekürzt. Der volle Bericht enthält außerdem Hinweise, übersprungene Prüfungen, VirusTotal-Links und Issues zum Nachlesen.

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

- **Herkunft:** Alter des Kontos und des Projekts, Fork (Kopie eines anderen Projekts), umbenanntes Projekt, Nachahmung eines bekannteren Projekts.
- **Köder:** Themen wie Cracks, Cheats oder „Premium gratis“, passwortgeschützte Archive, Download-Knöpfe, die von GitHub wegführen.
- **Sterne:** Passen die Sterne zur echten Nutzung (Forks, Issues, Beiträge)? Gekaufte Sterne sind ein bekannter Trick.
- **Releases** (veröffentlichte Downloads): Prüfsummen (eine Art Fingerabdruck einer Datei), Signaturen, Herkunftsnachweise des Builds (build provenance), wer die Dateien hochgeladen hat und ob eine Datei nachträglich ausgetauscht wurde.
- **VirusTotal** (optional): Abgleich der Datei-Fingerabdrücke mit bekannten Ergebnissen.
- **Quellcode:** Suche nach typischen Mustern von Schadsoftware, etwa versteckter oder verschlüsselter Code, Zugriff auf Passwörter zusammen mit einem Kanal nach außen, unsichtbare Zeichen und Text, der KI-Assistenten beeinflussen soll.
- **Issues:** Meldungen anderer Nutzer zu Viren oder Malware.
- **OpenSSF Scorecard** und **Trivy** (optional): öffentliche Sicherheitsbewertung und Schwachstellen-Scan.

Die vollständige Liste aller Einzelprüfungen steht in [docs/CHECKS.md](docs/CHECKS.md).

## Optional: GitHub-Token, VirusTotal, Trivy

**GitHub-Token.** Ohne Anmeldung erlaubt GitHub nur wenige Anfragen pro Stunde. Das reicht für etwa sechs Checks pro Stunde. Wenn du die [GitHub CLI](https://cli.github.com) installiert und mit `gh auth login` angemeldet bist, nutzt repo-check das automatisch. Sonst kannst du einen Token (eine Art Passwort nur für Programme) in `GITHUB_TOKEN` hinterlegen. Für öffentliche Repositories braucht er keine Berechtigungen.

**VirusTotal.** Leg ein kostenloses Konto auf [virustotal.com](https://www.virustotal.com) an und kopier den API-Schlüssel aus deinem Profil. Dann:

- Windows: `setx VT_API_KEY "dein-schlüssel"` und danach ein neues Terminal öffnen.
- macOS/Linux: `export VT_API_KEY="dein-schlüssel"` (für dauerhaft in `~/.zshrc` oder `~/.bashrc` eintragen).

Das kostenlose Kontingent ist klein. Hochgeladen wird nichts, siehe Datenschutz.

**Trivy.** Installier [Trivy](https://trivy.dev) nach der offiziellen Anleitung. Liegt es nicht im Suchpfad, gib den Ort in `TRIVY_PATH` an.

Weitere Umgebungsvariablen: `REPO_CHECK_LANG` (Standardsprache), `NO_COLOR` (keine Farben).

## Datenschutz

Was deinen Rechner verlässt:

- **Anfragen an GitHub** (`api.github.com`, für den Quellcode `codeload.github.com`) zum Repository, das du nennst: Projektdaten, Konto, Releases, Issues, Quellcode. Dazu eine Suche nach Projekten mit ähnlichem Namen, um Kopien zu erkennen. Mit Token sieht GitHub, welches Konto fragt.
- **VirusTotal** (`www.virustotal.com`): nur wenn `VT_API_KEY` gesetzt ist, und nur die Prüfsummen (Fingerabdrücke) von höchstens drei Release-Dateien. Es werden keine Dateien hochgeladen.
- **OpenSSF Scorecard** (`api.securityscorecards.dev`): eine Abfrage der öffentlichen Bewertung für das Repository, außer mit `--no-scorecard`.

Sonst nichts: keine Statistik, kein Konto, kein Server von uns. Trivy läuft lokal; es holt sich aber selbst das Repository und seine Schwachstellen-Datenbank. Ist kein Token hinterlegt, fragt repo-check lokal die GitHub CLI nach deinem Login (`gh auth token`); der Token geht nur an `api.github.com`.

## Häufige Fragen

**Grün heißt nicht sicher. Was heißt es dann?**
Grün heißt „keine Warnzeichen gefunden“. Der Check sieht das Repository und die Angaben zu den Downloads, nicht das, was ein Programm auf deinem Rechner tut. Starte unbekannte Windows-Programme zuerst in einer abgeschotteten Umgebung wie der [Windows-Sandbox](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/) (ab Windows Pro, nicht in Windows Home).

**Warum bekommt ein bekanntes Tool Gelb?**
Gelb heißt nicht „Schadsoftware“, sondern „lies die Gründe“. Typische Fälle bei seriösen Projekten: Das Projekt ist erst wenige Wochen alt. Im Quellcode liegt eine fertige Programmdatei, die niemand nachprüfen kann. Oder einige Virenscanner bei VirusTotal schlagen bei einer unsignierten Datei an, was oft ein Fehlalarm ist, sich von außen aber nicht entscheiden lässt.

**Wird etwas aus dem geprüften Projekt ausgeführt?**
Nein. repo-check liest nur. Es lädt keine Programme herunter, um sie zu starten.

**Warum untersucht repo-check die fertige Programmdatei nicht selbst?**
Um zu beurteilen, was eine .exe tut, muss man sie zerlegen oder in einer abgeschotteten Umgebung laufen lassen. Das ist die Arbeit von Virenscannern. Ein Skript, das nur in die Datei hineinschaut, würde eine Sicherheit vortäuschen, die es nicht liefern kann. repo-check nimmt deshalb den Fingerabdruck (SHA-256), den GitHub zur Download-Datei angibt, und fragt bei VirusTotal nach, was die Virenscanner dort zu genau dieser Datei sagen. Dafür brauchst du einen VirusTotal-Schlüssel. Ohne Schlüssel, oder wenn VirusTotal die Datei noch nicht kennt, steht das im Bericht, zusammen mit einem Link zum Selbernachsehen. Bei älteren Releases fehlt der Fingerabdruck auf GitHub manchmal; dann ist keine Abfrage möglich. Trivy ist kein Virenscanner: Es sucht im Quellcode nach bekannten Sicherheitslücken in verwendeten Bibliotheken und nach versehentlich veröffentlichten Zugangsdaten.

**Was kommt heraus, wenn repo-check sich selbst prüft?**
Stand Version 1.0.0: Grün. Solange das Projekt neu ist, steht dabei, dass es erst wenige Tage oder Wochen alt ist. Dazu kommen zwei Hinweise aus dem eigenen Material: In den Tests stehen Beispiele für Schadcode-Muster, und der Prompt für Chat-Assistenten zitiert typische Manipulationssätze, um vor ihnen zu warnen. Die Mustersuche erkennt beides und zeigt es als Hinweis, nicht als Warnzeichen. Probier es aus: `python repo_check.py Hamido212/repo-check`.

**Geht das auch mit GitLab oder anderen Seiten?**
Nein, nur GitHub.

**Kann ich das Ergebnis mit einer KI besprechen?**
Ja: `python repo_check.py owner/repo --md` ausführen und den Bericht mit [diesem Prompt](prompts/chat-assistant.md) in deinen Chat einfügen.

## Mitmachen

Fehler, falsche Warnungen oder übersehene Schadsoftware: siehe [CONTRIBUTING.md](CONTRIBUTING.md) und [SECURITY.md](SECURITY.md). Sicherheitslücken im Tool selbst bitte nicht öffentlich melden, sondern über die private Meldung auf GitHub.

## Lizenz

[MIT](LICENSE) © 2026 Hamid Yosefsei (HYOS)
