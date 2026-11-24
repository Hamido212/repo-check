# repo-check: checks / Prüfungen

_Generated from the engine by `python tests/generate_checks_md.py`. Do not edit by hand; `python repo_check.py --list-checks --lang en|de` prints the same tables._

# English

## Checks

Risk findings add their weight to an internal risk score (higher is worse; it is not a safety percentage and is only part of the JSON output). Below 25: green. 25 to 59: yellow. 60 and more: red. Repository not found or core checks failed without other evidence: unknown. Capabilities are shown like app permissions and only count in combinations. Trust signals never offset unrelated risk.

| ID | Category | What it means | Effect on the verdict |
|---|---|---|---|
| `origin.not_found` | Origin | Repository not found: deleted, private or misspelled. A deleted repo is not proof of malware, but nothing can be checked. Don't download copies from elsewhere. | verdict unknown |
| `origin.unreachable` | Origin | Could not read the repository data from GitHub. Without the basic data no verdict is possible. The skipped checks say why. | verdict unknown |
| `origin.renamed` | Origin | The repository moved or was renamed; it is now …. Old links still redirect. Link the new address. | information only |
| `origin.fork` | Origin | This is a fork (a copy) of …. Make sure you want the copy and not the original. | +10 points |
| `origin.archived` | Origin | Archived: no longer maintained. Security problems will not be fixed anymore. | information only |
| `origin.young_repo` | Origin | Brand new: the repository is only … days old. Very new projects have had little outside attention yet. | +15 points |
| `origin.young_account` | Origin | The owner's account is only … days old. Throwaway accounts are a common way to spread malware. | +10/20/35 points, depending on severity |
| `origin.thin_account` | Origin | The owner's account has almost no history (… public repos, … followers). Not bad by itself, but nothing vouches for the author. | +10 points |
| `origin.owner_unavailable` | Origin | The owner's account data could not be read. Account age and history are not part of this verdict. | information only |
| `origin.no_license` | Origin | No license: it is legally unclear what you may do with it. This is about rights, not safety. | information only |
| `origin.stale` | Origin | Last change … days ago. Unmaintained projects don't get security fixes. | information only |
| `lure.topic` | Bait | The name or description is about cracks, cheats or free in-game currency. These are the most common bait for malware on GitHub. | +20 points |
| `lure.archive_password` | Bait | Text near the download gives a password for an archive. Password-protected archives hide malware from virus scanners. Real projects almost never do this. | +35 in program code, +35 in docs, +35 in tests, vendored code, CI or build tooling |
| `lure.external_download` | Bait | The README sends you to a download outside GitHub (file host or short link). Malware repos do this so the file is never checked on GitHub. | +20 in program code, +20 in docs, +20 in tests, vendored code, CI or build tooling |
| `lure.archive_in_repo` | Bait | Packed archive file(s) inside the source code: …. Malware repos often ship the payload as an archive in the repo instead of a release. | +10/15/40 points, depending on severity |
| `stars.too_few` | Stars | … stars: too few for a star analysis. Star counts only say something from a few hundred on. | information only |
| `stars.boom` | Stars | Star explosion: … stars in … days. Can be a real hit or bought stars; the usage traces decide. | +10 points |
| `stars.hollow` | Stars | Many stars but hardly any real use: …. Typical for bought stars, which make malware repos look trustworthy. | +25/45 points, depending on severity |
| `stars.thin` | Stars | One usage value is thin (…); the rest fits. A single thin value is normal. | information only |
| `stars.few_contributors` | Stars | … stars but only … contributors. Real hits usually attract more helpers quickly. | +10 points |
| `impersonation.likely_copy` | Copies | Possible copy: … has the same name, is older and much more popular (… stars). Copies of popular tools with a modified download are a common trick. Get the program from the original. | +45 points |
| `impersonation.same_name` | Copies | Another, more popular project has the same name: …. Make sure this is the project you mean. | information only |
| `release.none` | Release | No releases: there is no ready-made download, only source code. Only build it yourself or use official sources, never re-uploads. | information only |
| `release.latest` | Release | Latest release from …, … files. The tag name comes from the repo and is shown as data. | information only |
| `release.fresh` | Release | The release is only … days old. Very fresh releases have hardly been checked by anyone. | information only |
| `release.no_checksum` | Release | No checksums for the download files. You can't verify that a file is the one the author published. | +3 points |
| `release.manual_upload` | Release | Files were uploaded by hand (…), not by an automated build. Then nobody can verify the file was built from the code shown. | +3 points |
| `release.asset_replaced` | Release | A download file was uploaded or changed … days after the release was published. Normal for late additions, but also the trace of a swapped file. Weighs more when the uploader is neither a regular contributor nor the person who uploaded the release's other files. | +8/25 points, depending on severity |
| `release.not_on_default_branch` | Release | The release tag points to code that is not on the main branch. Common with release branches; it means the code on the main page is not exactly what was released. | +3 points |
| `release.risky_asset` | Release | The release offers a file type that is rarely legitimate for downloads (script or shortcut). Screensavers, shortcuts and HTA files are almost only used for malware. | +10/40 points, depending on severity |
| `release.double_extension` | Release | A download file hides its real type behind a double extension. Like photo.jpg.exe: a classic malware trick. | +60 points |
| `vt.detections` | VirusTotal | VirusTotal: … of … scanners flag a download file. 1-2 hits are often false alarms for unsigned hobby tools; many hits are a real warning. | +12/30/50/100 points, depending on severity |
| `vt.unknown_file` | VirusTotal | VirusTotal doesn't know … download file(s) yet. Nobody has scanned it there yet. You can upload it yourself; release files are public anyway. | +5 points |
| `vt.no_digest` | VirusTotal | GitHub has no checksum for these files, so no VirusTotal lookup was possible. Check the file yourself on virustotal.com after downloading. | information only |
| `vt.unsigned` | VirusTotal | The Windows download is not digitally signed. Windows shows a warning on first start. Common for hobby projects. | information only |
| `code.encoded_ps` | Code | Hidden, encoded PowerShell command. Malware uses this to hide what it runs. | +100 in program code, +50 in docs, +30 in tests, vendored code, CI or build tooling |
| `code.ps_hidden_download` | Code | PowerShell in a hidden window downloads something. Typical first stage of malware. | +60 in program code, +20 in docs, +15 in tests, vendored code, CI or build tooling |
| `code.b64_exec` | Code | Runs code that is hidden in encoded or packed form. Hidden code can't be reviewed; malware droppers work this way. | +60 in program code, +15 in docs, +15 in tests, vendored code, CI or build tooling |
| `code.remote_exec_py` | Code | Python downloads code and runs it directly. What runs is decided later on a server, not in the code you see. | +60 in program code, +15 in docs, +15 in tests, vendored code, CI or build tooling |
| `code.remote_exec_js` | Code | JavaScript downloads code and runs it directly. What runs is decided later on a server, not in the code you see. | +50 in program code, +10 in docs, +10 in tests, vendored code, CI or build tooling |
| `code.lolbin_download` | Code | Uses Windows system tools (certutil, mshta, bitsadmin, regsvr32) to download or run things. A known trick to slip past antivirus. | +50 in program code, +10 in docs, +10 in tests, vendored code, CI or build tooling |
| `code.defender_off` | Code | Switches off Windows Defender or the firewall, or adds Defender exclusions. Normal programs don't need this. Malware does. | +100 in program code, +30 in docs, +10 in tests, vendored code, CI or build tooling |
| `code.uac_bypass` | Code | Known trick to bypass the Windows admin prompt (UAC). Programs that need admin rights should ask for them. | +40 in program code, +5 in docs, +5 in tests, vendored code, CI or build tooling |
| `code.remote_exec_ps` | Code | PowerShell one-liner that downloads and runs code right away. Common in install instructions (look before you paste); unusual inside a program. | +10 in program code, +0 in docs, +0 in tests, vendored code, CI or build tooling |
| `code.remote_exec_sh` | Code | Shell one-liner (curl / sh) that downloads and runs a script. Common in install instructions (look before you paste); unusual inside a program. | +5 in program code, +0 in docs, +0 in tests, vendored code, CI or build tooling |
| `code.raw_ip` | Code | Connects directly to a public IP address instead of a domain name. Sometimes harmless, sometimes a hidden server. | +3 in program code, +0 in docs, +0 in tests, vendored code, CI or build tooling |
| `code.big_blob` | Code | Large encoded data block in the code. Often images or fonts, sometimes hidden code. | +5 in program code, +0 in docs, +0 in tests, vendored code, CI or build tooling |
| `code.discord_webhook` | Code | Contains a Discord webhook address. Stealers use webhooks to send stolen data; bots use them too. | +10 in program code, +0 in docs, +0 in tests, vendored code, CI or build tooling |
| `code.paste_service` | Code | Loads raw text from paste sites. Paste sites are a common hiding place for the next stage of malware. | +10 in program code, +0 in docs, +0 in tests, vendored code, CI or build tooling |
| `code.exfil_service` | Code | Uses anonymous upload, webhook-catcher or tunnel services. A common way to send stolen data out without an own server. | +10 in program code, +0 in docs, +0 in tests, vendored code, CI or build tooling |
| `code.telegram_bot` | Code | Talks to the Telegram bot API. Legit for bots; also a way to send stolen data. | capability: no points alone, counts in combinations |
| `code.browser_creds` | Code | Reads browser data such as saved logins or cookies. Downloaders use cookies for logged-in content; stealers use the same files. | capability: no points alone, counts in combinations |
| `code.dpapi` | Code | Decrypts protected Windows data. Used to read saved passwords; also used by password tools. | capability: no points alone, counts in combinations |
| `code.wallets` | Code | Looks for crypto wallets or Telegram sessions. Fine for wallet software, a red flag anywhere else. | capability: no points alone, counts in combinations |
| `code.discord_token` | Code | Reads Discord login data. Discord token theft is very common in GitHub malware. | capability: no points alone, counts in combinations |
| `code.keyboard` | Code | Watches keyboard input. Normal for hotkey tools, also the core of a keylogger. | capability: no points alone, counts in combinations |
| `code.autostart` | Code | Adds itself to autostart. Normal for tray tools. | capability: no points alone, counts in combinations |
| `code.setup_subprocess` | Code | setup.py runs system commands during installation. Common for building native extensions. | capability: no points alone, counts in combinations |
| `code.obfuscated_js` | Code | Deliberately obfuscated JavaScript. Typical for hidden malware; normal minifiers don't produce this. | +35 in program code, +10 in docs, +10 in tests, vendored code, CI or build tooling |
| `code.hidden_bidi` | Code | Hidden text-direction characters in source code (Trojan Source). They make code look different from what it does. | +70 in program code, +10 in docs, +3 in tests, vendored code, CI or build tooling |
| `code.invisible_payload` | Code | Long runs of invisible characters in source code. A technique to smuggle hidden code past reviewers (e.g. GlassWorm). | +80 in program code, +20 in docs, +20 in tests, vendored code, CI or build tooling |
| `code.zero_width` | Code | Invisible zero-width characters in source code. Usually accidental, sometimes used to hide differences. | +3 in program code, +0 in docs, +0 in tests, vendored code, CI or build tooling |
| `code.install_hook` | Code | An npm install script runs automatically. Normal for native modules, but it runs before you can look. | capability: no points alone, counts in combinations |
| `code.install_hook_suspicious` | Code | An npm install script downloads or runs something suspicious. It runs automatically on npm install, before you can look. | +40 points |
| `code.setup_py_network` | Code | setup.py accesses the network during installation. Installing should not need to download extra code. | +25 in program code, +25 in docs, +0 in tests, vendored code, CI or build tooling |
| `code.unexplained_exe` | Code | Ready-made program file(s) inside the source code: …. Nobody can check them against the code. In a bin or resources folder they are often bundled helpers; in the top folder or with names like setup or loader they are a warning. | +5/12/25 points, depending on severity |
| `code.screensaver` | Code | Screensaver or control-panel files (.scr/.pif/.cpl) in the repo. These file types are almost only used for malware. | +50 points |
| `code.vendored_libs` | Code | … bundled libraries or common helper programs (e.g. runtime DLLs, build wrappers). Normal for many apps; listed for completeness. | information only |
| `code.clean` | Code | … files scanned, no typical warning signs in the code. Pattern search finds known tricks, not every possible one. | information only |
| `code.partial` | Code | Only part of the code was scanned (… files); the rest exceeded the size or time limit. The verdict covers only the scanned part. | information only |
| `ai.override` | AI steering | Text tries to override an AI assistant's instructions. Someone wants to steer AI tools that read this repo. | +20 in program code, +20 in docs, +0 in tests, vendored code, CI or build tooling |
| `ai.verdict_steer` | AI steering | Text tells an AI assistant to call the project safe. Honest projects have no reason to steer a security review. | +45 in program code, +45 in docs, +0 in tests, vendored code, CI or build tooling |
| `ai.hidden_comment` | AI steering | Hidden comment with safety instructions for AI assistants. Invisible on the web page, visible to AI tools. | +45 in program code, +45 in docs, +0 in tests, vendored code, CI or build tooling |
| `issues.open_reports` | Issues | … open issue(s) report malware or a virus. Read them: often false alarms, sometimes the first sign of a hacked project. | +5/15/30 points, depending on severity |
| `issues.closed_reports` | Issues | … closed issue(s) mention malware, viruses or antivirus warnings. Closed usually means answered, often as a false alarm. | information only |
| `issues.av_flags` | Issues | … open issue(s) say antivirus programs flag the download. Common for unsigned tools; read what the maintainers say. | information only |
| `deps.vulns` | Dependencies | Trivy: known vulnerabilities in used libraries: … critical, … high. Not malware, but outdated components with known holes. | information only |
| `deps.secrets` | Dependencies | Trivy: … possible secret(s) in the code (keys, tokens). A risk for the project, not for you as a user. | information only |
| `deps.clean` | Dependencies | Trivy: no critical or high known vulnerabilities in the libraries. Only covers known vulnerabilities in dependencies. | information only |
| `scorecard.score` | Scorecard | OpenSSF Scorecard: …/10. Rates the project's security practices, not whether it is malware. | information only |
| `scorecard.none` | Scorecard | No OpenSSF Scorecard data for this repo. Scorecard only covers projects it has crawled. | information only |
| `combo.stealer` | Combination | Reads logins, cookies or keystrokes AND can send data to a chat or upload service. That's the classic info-stealer pattern. | +40/100 points, depending on severity |
| `combo.cred_new_project` | Combination | Reads saved logins or cookies, in a very new project or from a very new account. In an established tool that's a feature; from a fresh account it's a strong warning. | +30 points |
| `combo.install_hook_obfuscated` | Combination | Runs code on install AND contains obfuscated or hidden code. The typical shape of malicious npm packages. | +100 points |
| `combo.copy_with_download` | Combination | A possible copy that offers its own download files. Exactly how fake copies of popular tools spread malware. | +20 points |
| `trust.attested` | Trust | Build provenance is attested for … file(s). Proves the file was built by GitHub Actions from this repo. Verify: gh attestation verify <file> --repo … | trust signal: cancels release.no_checksum, release.manual_upload |
| `trust.immutable` | Trust | The release is immutable: its files can't be swapped afterwards. GitHub enforces this for immutable releases. | trust signal: cancels release.no_checksum |
| `trust.signed` | Trust | Signature files are included in the release. Lets you verify the files with the author's key. | trust signal: cancels release.no_checksum |
| `trust.ci_built` | Trust | All files were uploaded by GitHub Actions (automated build). Makes a hand-swapped file less likely; it is not proof. | trust signal: no points |
| `trust.tag_on_default` | Trust | The release tag points to code on the main branch. The release matches code anyone can read. | trust signal: no points |
| `trust.established_account` | Trust | Established account: since …, … public repos, … followers. Accounts can be bought or hacked, so this never offsets risk. | trust signal: no points |
| `trust.established_project` | Trust | Established project: … years old, … contributors. Many eyes over a long time. | trust signal: no points |
| `trust.real_usage` | Trust | Usage traces fit the stars (… forks, … watchers). Real users leave forks, watchers and issues behind. | trust signal: no points |
| `trust.vt_clean` | Trust | VirusTotal: no scanner flags the checked files. New malware is often not detected yet. | trust signal: no points |
| `trust.scorecard` | Trust | OpenSSF Scorecard: …/10. Good security practices; says nothing about intent. | trust signal: no points |
| `cap.credential_access` | Capability | Reads saved browser data, passwords, wallets or login tokens. Fine when it is the tool's job (e.g. a downloader using your cookies), but know that it can. | capability: no points alone, counts in combinations |
| `cap.keyboard_capture` | Capability | Can watch keyboard input. Normal for hotkey and macro tools. | capability: no points alone, counts in combinations |
| `cap.exfil_channel` | Capability | Can send data to chat or upload services (webhook, Telegram bot, paste site). Normal for bots and notifiers. | capability: no points alone, counts in combinations |
| `cap.autostart` | Capability | Can add itself to autostart. Normal for tray tools; you should be able to switch it off. | capability: no points alone, counts in combinations |
| `cap.install_hook` | Capability | Runs code automatically on installation (npm script or setup.py). Common for native modules; it runs before you can look. | capability: no points alone, counts in combinations |
| `cap.remote_installer` | Capability | The install instructions use a one-liner that downloads and runs a script. Open the script URL and read it before pasting the command. | capability: no points alone, counts in combinations |

# Deutsch

## Prüfungen

Risiko-Funde zählen mit ihrem Gewicht zu einer internen Risiko-Punktzahl (höher ist schlechter; kein Sicherheits-Prozentwert, steht nur in der JSON-Ausgabe). Unter 25: grün. 25 bis 59: gelb. Ab 60: rot. Repo nicht gefunden oder wichtige Prüfungen gescheitert ohne andere Funde: unbekannt. Fähigkeiten werden wie App-Berechtigungen gezeigt und zählen nur in Kombinationen. Vertrauenssignale gleichen nie fremde Risiken aus.

| ID | Bereich | Was es bedeutet | Wirkung auf die Bewertung |
|---|---|---|---|
| `origin.not_found` | Herkunft | Repo nicht gefunden: gelöscht, privat oder falsch geschrieben. Ein gelöschtes Repo beweist keine Schadsoftware, aber prüfen lässt sich nichts. Lade keine Kopien von anderswo. | Bewertung unbekannt |
| `origin.unreachable` | Herkunft | Die Repo-Daten ließen sich nicht von GitHub abrufen. Ohne die Grunddaten ist keine Bewertung möglich. Bei den übersprungenen Prüfungen steht der Grund. | Bewertung unbekannt |
| `origin.renamed` | Herkunft | Das Repo ist umgezogen oder wurde umbenannt, jetzt: …. Alte Links leiten noch weiter. Verlinke die neue Adresse. | nur Information |
| `origin.fork` | Herkunft | Das ist ein Fork (eine Kopie) von …. Prüf, ob du wirklich die Kopie willst und nicht das Original. | +10 Punkte |
| `origin.archived` | Herkunft | Archiviert: wird nicht mehr gepflegt. Sicherheitslücken werden nicht mehr behoben. | nur Information |
| `origin.young_repo` | Herkunft | Brandneu: Das Repo ist erst … Tage alt. Sehr neue Projekte hat noch kaum jemand von außen angeschaut. | +15 Punkte |
| `origin.young_account` | Herkunft | Das Konto dahinter ist erst … Tage alt. Wegwerf-Konten sind ein üblicher Weg, Schadsoftware zu verteilen. | +10/20/35 Punkte, je nach Schwere |
| `origin.thin_account` | Herkunft | Das Konto hat kaum Geschichte (… öffentliche Repos, … Follower). Für sich nicht schlimm, aber nichts spricht für den Autor. | +10 Punkte |
| `origin.owner_unavailable` | Herkunft | Die Kontodaten des Besitzers ließen sich nicht abrufen. Alter und Geschichte des Kontos fehlen in dieser Bewertung. | nur Information |
| `origin.no_license` | Herkunft | Keine Lizenz: Rechtlich ist unklar, was du damit darfst. Das betrifft Rechte, nicht Sicherheit. | nur Information |
| `origin.stale` | Herkunft | Letzte Änderung vor … Tagen. Ungepflegte Projekte bekommen keine Sicherheits-Updates. | nur Information |
| `lure.topic` | Köder | Name oder Beschreibung dreht sich um Cracks, Cheats oder Gratis-Spielwährung. Das ist der häufigste Köder für Schadsoftware auf GitHub. | +20 Punkte |
| `lure.archive_password` | Köder | Beim Download steht ein Passwort für ein Archiv. Archive mit Passwort verstecken Schadsoftware vor Virenscannern. Echte Projekte machen das fast nie. | +35 im Programmcode, +35 in Doku, +35 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `lure.external_download` | Köder | Die Anleitung schickt dich zu einem Download außerhalb von GitHub (Filehoster oder Kurzlink). Schadsoftware-Repos machen das, damit die Datei nie auf GitHub geprüft wird. | +20 im Programmcode, +20 in Doku, +20 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `lure.archive_in_repo` | Köder | Gepackte Archiv-Datei(en) direkt im Quellcode: …. Schadsoftware-Repos legen die Ladung oft als Archiv ins Repo statt in ein Release. | +10/15/40 Punkte, je nach Schwere |
| `stars.too_few` | Sterne | … Sterne: zu wenige für eine Sterne-Analyse. Sterne sagen erst ab ein paar Hundert etwas aus. | nur Information |
| `stars.boom` | Sterne | Sterne-Explosion: … Sterne in … Tagen. Kann ein echter Hit sein oder gekaufte Sterne; die Nutzungsspuren entscheiden. | +10 Punkte |
| `stars.hollow` | Sterne | Viele Sterne, aber kaum echte Nutzung: …. Typisch für gekaufte Sterne, mit denen Schadsoftware-Repos seriös wirken sollen. | +25/45 Punkte, je nach Schwere |
| `stars.thin` | Sterne | Ein Nutzungswert ist dünn (…), der Rest passt. Ein einzelner dünner Wert ist normal. | nur Information |
| `stars.few_contributors` | Sterne | … Sterne, aber nur … Mitwirkende. Bei echten Hits machen meist schnell mehr Leute mit. | +10 Punkte |
| `impersonation.likely_copy` | Kopien | Mögliche Kopie: … heißt genauso, ist älter und viel beliebter (… Sterne). Kopien beliebter Tools mit verändertem Download sind ein üblicher Trick. Hol dir das Programm vom Original. | +45 Punkte |
| `impersonation.same_name` | Kopien | Ein anderes, beliebteres Projekt heißt genauso: …. Prüf, ob das hier das Projekt ist, das du meinst. | nur Information |
| `release.none` | Release | Keine Releases: Es gibt keinen fertigen Download, nur Quellcode. Selbst bauen oder offizielle Quellen nutzen, nie fremde Uploads. | nur Information |
| `release.latest` | Release | Neuestes Release vom …, … Dateien. Der Tag-Name kommt aus dem Repo und wird als Daten gezeigt. | nur Information |
| `release.fresh` | Release | Das Release ist erst … Tage alt. Ganz frische Releases hat noch kaum jemand geprüft. | nur Information |
| `release.no_checksum` | Release | Keine Prüfsummen für die Download-Dateien. Du kannst nicht nachprüfen, ob die Datei die ist, die der Autor veröffentlicht hat. | +3 Punkte |
| `release.manual_upload` | Release | Die Dateien wurden von Hand hochgeladen (…), nicht von einem automatischen Build. Dann lässt sich nicht nachprüfen, ob die Datei aus dem gezeigten Code gebaut wurde. | +3 Punkte |
| `release.asset_replaced` | Release | Eine Download-Datei wurde … Tage nach dem Release hochgeladen oder geändert. Bei Nachträgen normal, aber auch die Spur einer ausgetauschten Datei. Zählt mehr, wenn der Hochlader weder regelmäßig mitarbeitet noch die übrigen Release-Dateien hochgeladen hat. | +8/25 Punkte, je nach Schwere |
| `release.not_on_default_branch` | Release | Der Release-Tag zeigt auf Code, der nicht im Hauptzweig liegt. Bei Release-Zweigen üblich; heißt aber, dass der Code auf der Startseite nicht genau dem Release entspricht. | +3 Punkte |
| `release.risky_asset` | Release | Das Release bietet einen Dateityp an, der für Downloads selten seriös ist (Skript oder Verknüpfung). Bildschirmschoner, Verknüpfungen und HTA-Dateien nutzt fast nur Schadsoftware. | +10/40 Punkte, je nach Schwere |
| `release.double_extension` | Release | Eine Download-Datei versteckt ihren echten Typ hinter einer doppelten Endung. Wie foto.jpg.exe: ein klassischer Schadsoftware-Trick. | +60 Punkte |
| `vt.detections` | VirusTotal | VirusTotal: … von … Scannern melden eine Download-Datei. 1-2 Treffer sind bei unsignierten Hobby-Tools oft Fehlalarm; viele Treffer sind eine echte Warnung. | +12/30/50/100 Punkte, je nach Schwere |
| `vt.unknown_file` | VirusTotal | VirusTotal kennt … Download-Datei(en) noch nicht. Dort hat sie noch niemand geprüft. Du kannst sie selbst hochladen, Release-Dateien sind ohnehin öffentlich. | +5 Punkte |
| `vt.no_digest` | VirusTotal | GitHub hat für diese Dateien keine Prüfsumme, deshalb ging keine VirusTotal-Abfrage. Prüf die Datei nach dem Download selbst auf virustotal.com. | nur Information |
| `vt.unsigned` | VirusTotal | Der Windows-Download ist nicht digital signiert. Windows warnt beim ersten Start. Bei Hobby-Projekten üblich. | nur Information |
| `code.encoded_ps` | Code | Versteckter, verschlüsselter PowerShell-Befehl. So versteckt Schadsoftware, was sie ausführt. | +100 im Programmcode, +50 in Doku, +30 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.ps_hidden_download` | Code | PowerShell lädt in einem versteckten Fenster etwas herunter. Typische erste Stufe von Schadsoftware. | +60 im Programmcode, +20 in Doku, +15 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.b64_exec` | Code | Führt Code aus, der verschlüsselt oder gepackt versteckt ist. Versteckten Code kann niemand prüfen; so arbeiten Schadsoftware-Lader. | +60 im Programmcode, +15 in Doku, +15 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.remote_exec_py` | Code | Python lädt Code herunter und führt ihn direkt aus. Was läuft, entscheidet später ein Server, nicht der Code, den du siehst. | +60 im Programmcode, +15 in Doku, +15 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.remote_exec_js` | Code | JavaScript lädt Code herunter und führt ihn direkt aus. Was läuft, entscheidet später ein Server, nicht der Code, den du siehst. | +50 im Programmcode, +10 in Doku, +10 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.lolbin_download` | Code | Nutzt Windows-Bordmittel (certutil, mshta, bitsadmin, regsvr32), um etwas zu laden oder auszuführen. Ein bekannter Trick, um am Virenschutz vorbeizukommen. | +50 im Programmcode, +10 in Doku, +10 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.defender_off` | Code | Schaltet Windows Defender oder die Firewall ab oder legt Defender-Ausnahmen an. Normale Programme brauchen das nicht. Schadsoftware schon. | +100 im Programmcode, +30 in Doku, +10 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.uac_bypass` | Code | Bekannter Trick, um die Windows-Admin-Abfrage (UAC) zu umgehen. Programme, die Admin-Rechte brauchen, sollten danach fragen. | +40 im Programmcode, +5 in Doku, +5 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.remote_exec_ps` | Code | PowerShell-Einzeiler, der Code lädt und sofort ausführt. In Installationsanleitungen üblich (vorher ansehen), in einem Programm ungewöhnlich. | +10 im Programmcode, +0 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.remote_exec_sh` | Code | Shell-Einzeiler (curl / sh), der ein Skript lädt und sofort ausführt. In Installationsanleitungen üblich (vorher ansehen), in einem Programm ungewöhnlich. | +5 im Programmcode, +0 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.raw_ip` | Code | Verbindet sich direkt mit einer öffentlichen IP-Adresse statt einem Domainnamen. Manchmal harmlos, manchmal ein versteckter Server. | +3 im Programmcode, +0 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.big_blob` | Code | Großer verschlüsselter Datenblock im Code. Oft Bilder oder Schriften, manchmal versteckter Code. | +5 im Programmcode, +0 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.discord_webhook` | Code | Enthält eine Discord-Webhook-Adresse. Datendiebe schicken darüber Beute weg; Bots nutzen sie auch. | +10 im Programmcode, +0 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.paste_service` | Code | Lädt Rohtext von Paste-Seiten. Paste-Seiten sind ein beliebtes Versteck für die nächste Stufe von Schadsoftware. | +10 im Programmcode, +0 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.exfil_service` | Code | Nutzt anonyme Upload-, Webhook-Mitschnitt- oder Tunnel-Dienste. Ein üblicher Weg, gestohlene Daten ohne eigenen Server rauszuschicken. | +10 im Programmcode, +0 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.telegram_bot` | Code | Spricht mit der Telegram-Bot-Schnittstelle. Für Bots normal; aber auch ein Weg, Beute zu verschicken. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `code.browser_creds` | Code | Liest Browser-Daten wie gespeicherte Logins oder Cookies. Downloader nutzen Cookies für Inhalte mit Login; Datendiebe nutzen dieselben Dateien. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `code.dpapi` | Code | Entschlüsselt geschützte Windows-Daten. Damit liest man gespeicherte Passwörter; auch Passwort-Tools machen das. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `code.wallets` | Code | Sucht nach Krypto-Wallets oder Telegram-Sitzungen. Bei Wallet-Software normal, sonst ein Alarmzeichen. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `code.discord_token` | Code | Liest Discord-Anmeldedaten aus. Diebstahl von Discord-Tokens ist in GitHub-Schadsoftware sehr häufig. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `code.keyboard` | Code | Beobachtet Tastatureingaben. Bei Hotkey-Tools normal, aber auch der Kern eines Keyloggers. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `code.autostart` | Code | Trägt sich in den Autostart ein. Bei Taskleisten-Tools normal. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `code.setup_subprocess` | Code | setup.py führt bei der Installation Systembefehle aus. Beim Bauen nativer Erweiterungen üblich. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `code.obfuscated_js` | Code | Absichtlich verschleierter JavaScript-Code. Typisch für versteckte Schadsoftware; normale Minifier erzeugen so etwas nicht. | +35 im Programmcode, +10 in Doku, +10 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.hidden_bidi` | Code | Versteckte Textrichtungs-Zeichen im Quellcode (Trojan Source). Damit sieht Code anders aus, als er sich verhält. | +70 im Programmcode, +10 in Doku, +3 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.invisible_payload` | Code | Lange Folgen unsichtbarer Zeichen im Quellcode. Eine Technik, um versteckten Code an Prüfern vorbeizuschmuggeln (z. B. GlassWorm). | +80 im Programmcode, +20 in Doku, +20 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.zero_width` | Code | Unsichtbare Null-Breite-Zeichen im Quellcode. Meist versehentlich, manchmal zum Verstecken von Unterschieden. | +3 im Programmcode, +0 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.install_hook` | Code | Ein npm-Installationsskript läuft automatisch. Bei nativen Modulen normal, läuft aber, bevor du hinschauen kannst. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `code.install_hook_suspicious` | Code | Ein npm-Installationsskript lädt oder startet etwas Verdächtiges. Das läuft automatisch bei npm install, bevor du hinschauen kannst. | +40 Punkte |
| `code.setup_py_network` | Code | setup.py geht bei der Installation ins Internet. Eine Installation sollte keinen Code nachladen müssen. | +25 im Programmcode, +25 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `code.unexplained_exe` | Code | Fertige Programmdatei(en) direkt im Quellcode: …. Die kann niemand mit dem Code abgleichen. In einem bin- oder resources-Ordner sind es oft mitgelieferte Helfer; ganz oben oder mit Namen wie setup oder loader sind sie ein Warnzeichen. | +5/12/25 Punkte, je nach Schwere |
| `code.screensaver` | Code | Bildschirmschoner- oder Systemsteuerungs-Dateien (.scr/.pif/.cpl) im Repo. Diese Dateitypen nutzt fast nur Schadsoftware. | +50 Punkte |
| `code.vendored_libs` | Code | … mitgelieferte Bibliotheken oder übliche Hilfsprogramme (z. B. Laufzeit-DLLs, Build-Wrapper). Bei vielen Apps normal; nur der Vollständigkeit halber. | nur Information |
| `code.clean` | Code | … Dateien durchsucht, keine typischen Warnzeichen im Code. Die Mustersuche findet bekannte Tricks, nicht jeden denkbaren. | nur Information |
| `code.partial` | Code | Nur ein Teil des Codes wurde durchsucht (… Dateien); der Rest überschritt die Größen- oder Zeitgrenze. Die Bewertung gilt nur für den durchsuchten Teil. | nur Information |
| `ai.override` | KI-Steuerung | Text versucht, die Anweisungen eines KI-Assistenten auszuhebeln. Jemand will KI-Tools steuern, die dieses Repo lesen. | +20 im Programmcode, +20 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `ai.verdict_steer` | KI-Steuerung | Text fordert einen KI-Assistenten auf, das Projekt als sicher einzustufen. Ehrliche Projekte haben keinen Grund, eine Sicherheitsprüfung zu steuern. | +45 im Programmcode, +45 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `ai.hidden_comment` | KI-Steuerung | Versteckter Kommentar mit Sicherheits-Anweisungen an KI-Assistenten. Auf der Webseite unsichtbar, für KI-Tools sichtbar. | +45 im Programmcode, +45 in Doku, +0 in Tests, fremdem Code, CI oder Build-Werkzeug |
| `issues.open_reports` | Issues | … offene Issue(s) melden Schadsoftware oder einen Virus. Lies sie: oft Fehlalarm, manchmal das erste Zeichen eines gehackten Projekts. | +5/15/30 Punkte, je nach Schwere |
| `issues.closed_reports` | Issues | … geschlossene Issue(s) erwähnen Schadsoftware, Viren oder Virenwarnungen. Geschlossen heißt meist beantwortet, oft als Fehlalarm. | nur Information |
| `issues.av_flags` | Issues | … offene Issue(s) sagen, dass Virenscanner den Download melden. Bei unsignierten Tools häufig; lies, was die Entwickler dazu sagen. | nur Information |
| `deps.vulns` | Abhängigkeiten | Trivy: bekannte Lücken in verwendeten Bibliotheken: … kritisch, … hoch. Keine Schadsoftware, aber veraltete Bausteine mit bekannten Lücken. | nur Information |
| `deps.secrets` | Abhängigkeiten | Trivy: … mögliche(s) Geheimnis(se) im Code (Schlüssel, Tokens). Ein Risiko fürs Projekt, nicht für dich als Nutzer. | nur Information |
| `deps.clean` | Abhängigkeiten | Trivy: keine kritischen oder hohen bekannten Lücken in den Bibliotheken. Deckt nur bekannte Lücken in Abhängigkeiten ab. | nur Information |
| `scorecard.score` | Scorecard | OpenSSF Scorecard: …/10. Bewertet die Sicherheits-Gewohnheiten des Projekts, nicht ob es Schadsoftware ist. | nur Information |
| `scorecard.none` | Scorecard | Keine OpenSSF-Scorecard-Daten für dieses Repo. Scorecard kennt nur Projekte, die es schon erfasst hat. | nur Information |
| `combo.stealer` | Kombination | Liest Logins, Cookies oder Tastatureingaben UND kann Daten an Chat- oder Upload-Dienste schicken. Das ist das klassische Muster eines Datendiebs. | +40/100 Punkte, je nach Schwere |
| `combo.cred_new_project` | Kombination | Liest gespeicherte Logins oder Cookies, in einem sehr neuen Projekt oder von einem sehr neuen Konto. Bei einem etablierten Tool ist das eine Funktion; von einem frischen Konto eine deutliche Warnung. | +30 Punkte |
| `combo.install_hook_obfuscated` | Kombination | Führt bei der Installation Code aus UND enthält verschleierten oder versteckten Code. Die typische Form bösartiger npm-Pakete. | +100 Punkte |
| `combo.copy_with_download` | Kombination | Eine mögliche Kopie mit eigenen Download-Dateien. Genau so verbreiten falsche Kopien beliebter Tools Schadsoftware. | +20 Punkte |
| `trust.attested` | Vertrauen | Die Build-Herkunft ist für … Datei(en) belegt (Attestation). Belegt, dass GitHub Actions die Datei aus diesem Repo gebaut hat. Prüfen: gh attestation verify <datei> --repo … | Vertrauenssignal: hebt release.no_checksum, release.manual_upload auf |
| `trust.immutable` | Vertrauen | Das Release ist unveränderlich: Die Dateien lassen sich nachträglich nicht austauschen. Das erzwingt GitHub bei unveränderlichen Releases. | Vertrauenssignal: hebt release.no_checksum auf |
| `trust.signed` | Vertrauen | Dem Release liegen Signatur-Dateien bei. Damit lassen sich die Dateien mit dem Schlüssel des Autors prüfen. | Vertrauenssignal: hebt release.no_checksum auf |
| `trust.ci_built` | Vertrauen | Alle Dateien hat GitHub Actions hochgeladen (automatischer Build). Macht einen von Hand getauschten Download unwahrscheinlicher, ist aber kein Beweis. | Vertrauenssignal: keine Punkte |
| `trust.tag_on_default` | Vertrauen | Der Release-Tag zeigt auf Code im Hauptzweig. Das Release passt zu Code, den jeder lesen kann. | Vertrauenssignal: keine Punkte |
| `trust.established_account` | Vertrauen | Etabliertes Konto: seit …, … öffentliche Repos, … Follower. Konten lassen sich kaufen oder hacken, deshalb gleicht das kein Risiko aus. | Vertrauenssignal: keine Punkte |
| `trust.established_project` | Vertrauen | Etabliertes Projekt: … Jahre alt, … Mitwirkende. Viele Augen über lange Zeit. | Vertrauenssignal: keine Punkte |
| `trust.real_usage` | Vertrauen | Nutzungsspuren passen zu den Sternen (… Forks, … Beobachter). Echte Nutzer hinterlassen Forks, Beobachter und Issues. | Vertrauenssignal: keine Punkte |
| `trust.vt_clean` | Vertrauen | VirusTotal: Kein Scanner meldet die geprüften Dateien. Neue Schadsoftware wird oft noch nicht erkannt. | Vertrauenssignal: keine Punkte |
| `trust.scorecard` | Vertrauen | OpenSSF Scorecard: …/10. Gute Sicherheits-Gewohnheiten; sagt nichts über Absichten. | Vertrauenssignal: keine Punkte |
| `cap.credential_access` | Fähigkeit | Liest gespeicherte Browser-Daten, Passwörter, Wallets oder Login-Tokens. In Ordnung, wenn das die Aufgabe ist (z. B. ein Downloader mit deinen Cookies), aber du solltest es wissen. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `cap.keyboard_capture` | Fähigkeit | Kann Tastatureingaben beobachten. Bei Hotkey- und Makro-Tools normal. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `cap.exfil_channel` | Fähigkeit | Kann Daten an Chat- oder Upload-Dienste schicken (Webhook, Telegram-Bot, Paste-Seite). Bei Bots und Benachrichtigungs-Tools normal. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `cap.autostart` | Fähigkeit | Kann sich in den Autostart eintragen. Bei Taskleisten-Tools normal; du solltest es abschalten können. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `cap.install_hook` | Fähigkeit | Führt bei der Installation automatisch Code aus (npm-Skript oder setup.py). Bei nativen Modulen üblich; läuft, bevor du hinschauen kannst. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
| `cap.remote_installer` | Fähigkeit | Die Installationsanleitung nutzt einen Einzeiler, der ein Skript lädt und ausführt. Öffne die Skript-Adresse und lies sie, bevor du den Befehl einfügst. | Fähigkeit: allein keine Punkte, zählt in Kombinationen |
