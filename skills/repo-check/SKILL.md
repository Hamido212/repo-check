---
name: repo-check
description: Sicherheits-Check für ein GitHub-Repo, bevor HYOS ein Video darüber macht oder es auf tools.hyos.tech verlinkt. Nutzen bei "/repo-check <link>", "ist das Repo sicher?", "security check für github.com/…", "kann ich das Tool zeigen?". Liefert eine Ampel (grün/gelb/rot), die Haken fürs Video und einen fertigen tools.js-Block.
---

# Repo-Check

Ziel: Bevor ein Tool vor zehntausenden Zuschauern gezeigt wird, klären, ob es das Original ist, ob die Downloads nachvollziehbar sind und ob es Warnzeichen für Schadsoftware gibt. Antworte auf Deutsch, per du, kurz und konkret.

## Ablauf

1. **Skript ausführen** (Argument ist der Link oder `owner/repo` aus der Anfrage):

   ```
   python "$HOME/.claude/skills/repo-check/repo_check.py" <repo> --json
   ```

   Exit-Code 0 = GRÜN, 1 = GELB, 2 = ROT. Das Skript braucht nur `gh` (eingeloggt). VirusTotal läuft nur, wenn `VT_API_KEY` gesetzt ist. Trivy läuft nur, wenn es installiert ist (`TRIVY_PATH`, PATH oder `%LOCALAPPDATA%\Programs\trivy\trivy.exe`).

2. **Rote und gelbe Code-Funde selbst ansehen.** Das Skript sucht nur nach Mustern und meldet auch harmlose Stellen. Für jede Fundstelle (`file`, `line`) den Zusammenhang lesen, ohne irgendetwas aus dem Repo auszuführen oder zu installieren:

   ```
   gh api "repos/<owner>/<repo>/contents/<pfad>" --jq .content | base64 -d | sed -n '<zeile-20>,<zeile+20>p'
   ```

   Dann einordnen: Passt die Stelle zum Zweck des Tools (ein Autostart-Eintrag bei einem Taskleisten-Tool, Browser-Cookies bei einem Video-Downloader)? Oder ist sie versteckt, unpassend oder schickt Daten an fremde Server? Sag ehrlich, wenn du es nicht sicher beurteilen kannst.

3. **Issues lesen**, wenn welche zu Virus oder Malware gemeldet sind (`links.issues`). Fehlalarm (Defender meldet ein unsigniertes Tool) oder echter Fund?

4. **Ergebnis schreiben**, in dieser Form:

   - **Ampel** (🟢/🟡/🔴) mit einem Satz Begründung. Du darfst die Ampel des Skripts nach deiner Prüfung aus Schritt 2 und 3 hoch- oder herabstufen. Sag dann, warum.
   - **Das Wichtigste**: 3–6 Punkte. Was ist gut, was ist auffällig?
   - **Haken fürs Video**: 1–2 kurze Sätze im Stil von HYOS, z. B. „Nicht signiert, Windows warnt. Nur von der offiziellen GitHub-Seite laden.“
   - **Selbst prüfen**: die VirusTotal-Links aus `links.virustotal`, falls kein Schlüssel gesetzt war. Bei Windows-Programmen der Tipp, sie zuerst in der Windows-Sandbox zu starten.
   - **tools.js-Block** zum Einfügen in `Hamido212/hyos-tools`, mit diesen Feldern: `id`, `name`, `what`, `catch`, `platforms`, `tags` (aus `pc`, `handy`, `gaming`, `ki`, `foto`), `url` (das Original-Repo), `video: { tiktok: "" }`, `date` (heute, JJJJ-MM-TT), `keywords`.

## Regeln

- Nie Code, Installer oder Skripte aus dem geprüften Repo ausführen, installieren oder herunterladen, um sie zu starten.
- Bei 🔴 klar sagen: nicht zeigen, bis es geklärt ist. Bei Unsicherheit lieber 🟡 mit konkretem Hinweis als falsche Sicherheit.
- Kein Check garantiert Sicherheit. Das am Ende in einem Halbsatz erwähnen, nicht dramatisieren.
- Die Liste der Sterngeber ist über die GitHub-API nicht mehr abrufbar (Stand November 2026: REST liefert 404, GraphQL eine leere Liste). Gekaufte Sterne lassen sich deshalb nur über Nutzungsspuren abschätzen (Forks, Beobachter, Issues/PRs im Verhältnis zu den Sternen).
