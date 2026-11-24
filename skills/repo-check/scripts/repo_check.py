#!/usr/bin/env python3
"""
repo_check.py – Sicherheits-Schnellcheck für ein GitHub-Repo, bevor du ein Video darüber machst.

Nutzung (PowerShell):
    python $HOME\\.claude\\skills\\repo-check\\repo_check.py https://github.com/owner/repo
    python $HOME\\.claude\\skills\\repo-check\\repo_check.py owner/repo --json

Optionen:
    --json        Maschinenlesbare Ausgabe (nutzt /repo-check in Claude Code)
    --no-stars    Sterne-Analyse überspringen
    --no-code     Code-Scan überspringen
    --no-trivy    Trivy überspringen

Voraussetzungen:
    Python 3.10+ und die GitHub CLI (gh), eingeloggt.
Optional:
    VT_API_KEY    Kostenloser VirusTotal-Schlüssel → prüft Release-Dateien per Prüfsumme
    Trivy         trivy.exe im PATH, in TRIVY_PATH oder unter %LOCALAPPDATA%\\Programs\\trivy\\

Das Skript lädt nichts aus dem Repo herunter, um es auszuführen. Der Quellcode wird nur
im Arbeitsspeicher als Text gelesen.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

NOW = datetime.now(timezone.utc)
LEVEL_ICON = {"bad": "🔴", "warn": "🟡", "ok": "🟢", "info": "⚪"}
LEVEL_ORDER = {"bad": 0, "warn": 1, "info": 2, "ok": 3}


# ---------------------------------------------------------------- Hilfen

class NotFound(Exception):
    pass


class GhError(Exception):
    pass


def gh_api(path: str, accept: str | None = None, raw: bool = False, timeout: int = 120):
    cmd = ["gh", "api", path]
    if accept:
        cmd += ["-H", f"Accept: {accept}"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        raise GhError("GitHub CLI (gh) nicht gefunden. Installieren: winget install GitHub.cli")
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace")
        if "404" in err or "Not Found" in err:
            raise NotFound(path)
        raise GhError(err.strip()[:300])
    if raw:
        return r.stdout
    out = r.stdout.decode("utf-8", "replace").strip()
    return json.loads(out) if out else None


def parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def days_since(s: str | None) -> int | None:
    d = parse_date(s)
    return None if d is None else max(0, (NOW - d).days)


def de_num(n: int | float) -> str:
    return f"{n:,.0f}".replace(",", ".")


def de_date(s: str | None) -> str:
    d = parse_date(s)
    return d.strftime("%d.%m.%Y") if d else "?"


def parse_repo(arg: str) -> tuple[str, str]:
    s = arg.strip()
    m = re.search(r"github\.com[/:]([^/\s]+)/([^/\s#?]+)", s)
    if m:
        owner, repo = m.group(1), m.group(2)
    else:
        m = re.fullmatch(r"([^/\s]+)/([^/\s]+)", s)
        if not m:
            raise SystemExit(f"Kann '{arg}' nicht lesen. Erwartet: https://github.com/owner/repo oder owner/repo")
        owner, repo = m.group(1), m.group(2)
    repo = re.sub(r"\.git$", "", repo)
    return owner, repo


@dataclass
class Finding:
    level: str              # bad | warn | info | ok
    area: str               # Herkunft, Sterne, Releases, VirusTotal, Code, Issues, Trivy
    text: str
    detail: str = ""
    file: str = ""
    line: int = 0
    snippet: str = ""


@dataclass
class Report:
    repo: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    haken: list = field(default_factory=list)
    links: dict = field(default_factory=dict)
    verdict: str = ""
    verdict_text: str = ""

    def add(self, level, area, text, **kw):
        self.findings.append(Finding(level, area, text, **kw))

    def hake(self, text):
        if text not in self.haken:
            self.haken.append(text)


# ---------------------------------------------------------------- 1. Herkunft

def check_origin(rep: Report, owner: str, name: str) -> dict | None:
    try:
        r = gh_api(f"repos/{owner}/{name}")
    except NotFound:
        rep.add("bad", "Herkunft", "Repo nicht gefunden: gelöscht, privat oder falsch geschrieben.")
        rep.hake("Das Original-Projekt ist nicht mehr erreichbar.")
        return None

    full = r["full_name"]
    age = days_since(r.get("created_at"))
    pushed = days_since(r.get("pushed_at"))
    rep.repo = {
        "full_name": full,
        "url": r["html_url"],
        "description": r.get("description") or "",
        "homepage": r.get("homepage") or "",
        "stars": r.get("stargazers_count", 0),
        "forks": r.get("forks_count", 0),
        "watchers": r.get("subscribers_count", 0),
        "open_issues": r.get("open_issues_count", 0),
        "license": (r.get("license") or {}).get("spdx_id") or "",
        "language": r.get("language") or "",
        "created_at": r.get("created_at"),
        "pushed_at": r.get("pushed_at"),
        "age_days": age,
        "size_kb": r.get("size", 0),
        "default_branch": r.get("default_branch"),
        "archived": r.get("archived", False),
        "fork": r.get("fork", False),
        "owner": r["owner"]["login"],
        "owner_type": r["owner"]["type"],
    }

    if full.lower() != f"{owner}/{name}".lower():
        rep.add("warn", "Herkunft", f"Umgezogen oder umbenannt: jetzt {full}",
                detail="Alte Links leiten noch weiter, verlink aber die neue Adresse.")

    if r.get("fork"):
        parent = (r.get("parent") or {}).get("full_name", "?")
        rep.add("warn", "Herkunft", f"Ist ein Fork von {parent}.",
                detail="Prüf, ob du wirklich die Kopie zeigen willst und nicht das Original.")
        rep.hake(f"Das ist eine Abwandlung von {parent}.")

    if r.get("archived"):
        rep.add("warn", "Herkunft", "Archiviert: wird nicht mehr gepflegt.")
        rep.hake("Wird nicht mehr weiterentwickelt.")

    if age is not None:
        if age < 14:
            rep.add("warn", "Herkunft", f"Brandneu: erst seit {age} Tagen online (seit {de_date(r.get('created_at'))}).",
                    detail="Neue Projekte hatte noch kaum jemand im Blick.")
            rep.hake(f"Brandneu, erst seit {age} Tagen online.")
        else:
            rep.add("ok", "Herkunft", f"Online seit {de_date(r.get('created_at'))} ({de_num(age)} Tage).")

    if pushed is not None and pushed > 365:
        rep.add("info", "Herkunft", f"Letzte Änderung vor {de_num(pushed)} Tagen.")

    if not rep.repo["license"]:
        rep.add("info", "Herkunft", "Keine Lizenz angegeben: rechtlich ist unklar, was man damit darf.")

    # Konto des Besitzers
    try:
        u = gh_api(f"users/{r['owner']['login']}")
        u_age = days_since(u.get("created_at"))
        kind = "Organisation" if u.get("type") == "Organization" else "Konto"
        desc = (f"{kind} {u['login']}: seit {de_date(u.get('created_at'))}, "
                f"{u.get('public_repos', 0)} öffentliche Repos, {de_num(u.get('followers', 0))} Follower")
        rep.repo["owner_created_at"] = u.get("created_at")
        rep.repo["owner_public_repos"] = u.get("public_repos", 0)
        rep.repo["owner_followers"] = u.get("followers", 0)
        if u.get("type") == "User" and u_age is not None and u_age < 30:
            rep.add("bad", "Herkunft", f"Konto ist erst {u_age} Tage alt. {desc}",
                    detail="Typisch für Wegwerf-Konten, über die Schadsoftware verteilt wird.")
        elif u.get("type") == "User" and u_age is not None and u_age < 180:
            rep.add("warn", "Herkunft", f"Junges Konto ({u_age} Tage). {desc}")
        elif u.get("public_repos", 0) <= 1 and u.get("followers", 0) < 5:
            rep.add("warn", "Herkunft", f"Konto mit kaum Geschichte. {desc}")
        else:
            rep.add("ok", "Herkunft", desc)
    except (NotFound, GhError) as e:
        rep.add("warn", "Herkunft", f"Konto des Besitzers nicht abrufbar ({e}).")

    # Mitwirkende
    try:
        contrib = gh_api(f"repos/{full}/contributors?per_page=100&anon=1") or []
        n = len(contrib)
        rep.repo["contributors"] = n
        if rep.repo["stars"] > 2000 and n <= 2:
            rep.add("warn", "Herkunft", f"{de_num(rep.repo['stars'])} Sterne, aber nur {n} Mitwirkende.",
                    detail="Bei echten Hits machen meist schnell mehr Leute mit.")
    except (NotFound, GhError):
        pass

    return r


# ---------------------------------------------------------------- 2. Sterne

def check_stars(rep: Report):
    """Gekaufte Sterne erkennen. GitHub zeigt die Liste der Sterngeber nicht mehr öffentlich,
    deshalb vergleichen wir Sterne mit Spuren echter Nutzung: Forks, Beobachter, Issues/PRs."""
    stars = rep.repo.get("stars", 0)
    age = rep.repo.get("age_days") or 0
    forks = rep.repo.get("forks", 0)
    watchers = rep.repo.get("watchers", 0)
    full = rep.repo["full_name"]

    if stars < 300:
        rep.add("info", "Sterne", f"{de_num(stars)} Sterne: zu wenige für eine Sterne-Analyse.")
        return

    try:
        activity = (gh_api(f"search/issues?q={urllib.parse.quote(f'repo:{full}')}&per_page=1") or {}).get("total_count", 0)
    except (NotFound, GhError):
        activity = None
    rep.repo["issues_and_prs"] = activity

    signals = []
    if forks / stars < 0.01:
        signals.append(f"nur {de_num(forks)} Forks")
    if watchers and watchers / stars < 0.002:
        signals.append(f"nur {de_num(watchers)} Beobachter")
    if activity is not None and activity < max(10, stars / 1000):
        signals.append(f"nur {de_num(activity)} Issues/PRs insgesamt")

    per_day = stars / max(age, 1)
    boom = age < 60 and stars > 5000
    if boom:
        rep.add("warn", "Sterne", f"Sterne-Explosion: {de_num(stars)} Sterne in {age} Tagen ({de_num(per_day)} pro Tag).",
                detail="Kann ein echter Hit sein, aber auch gekaufte Sterne. Siehe Nutzungsspuren.")

    usage = f"{de_num(forks)} Forks, {de_num(watchers)} Beobachter" + (f", {de_num(activity)} Issues/PRs" if activity is not None else "")
    if len(signals) >= 2 and stars > 2000:
        rep.add("bad" if boom else "warn", "Sterne", f"Viele Sterne, aber kaum echte Nutzung: {', '.join(signals)}.",
                detail="Typisches Muster bei gekauften Sternen, mit denen Schadsoftware-Repos seriös wirken sollen.")
    elif signals and stars > 2000:
        rep.add("info", "Sterne", f"Ein Wert ist dünn ({', '.join(signals)}), der Rest passt ({usage}).")
    else:
        rep.add("ok", "Sterne", f"Nutzungsspuren passen zu den Sternen ({usage}).")


# ---------------------------------------------------------------- 3. Releases + VirusTotal

INSTALLER_RE = re.compile(r"\.(exe|msi|msix|appx|zip|7z|rar|apk|aab|appimage|dmg|pkg|deb|rpm|tar\.gz|tgz|jar|vsix|crx|xpi)$", re.I)
WINDOWS_RE = re.compile(r"\.(exe|msi|msix|appx)$|win(dows)?[-_.]?(x64|64|amd64|arm64)?.*\.(zip|7z)$", re.I)
ANDROID_RE = re.compile(r"\.(apk|aab)$", re.I)
CHECKSUM_RE = re.compile(r"(sha256|sha512|checksums?|sums)(\.txt)?$|\.sha(256|512)$", re.I)
SIGNATURE_RE = re.compile(r"\.(sig|asc|minisig|pem|sigstore(\.json)?|intoto\.jsonl|bundle)$", re.I)


def check_releases(rep: Report) -> list[dict]:
    full = rep.repo["full_name"]
    try:
        rels = [x for x in (gh_api(f"repos/{full}/releases?per_page=10") or []) if not x.get("draft")]
    except (NotFound, GhError):
        rels = []
    if not rels:
        rep.add("info", "Releases", "Keine Releases: Es gibt keinen fertigen Download, nur Quellcode.")
        rep.hake("Kein fertiger Download, man muss es selbst bauen.")
        return []

    stable = [x for x in rels if not x.get("prerelease")]
    rel = stable[0] if stable else rels[0]
    assets = rel.get("assets") or []
    rel_age = days_since(rel.get("published_at"))
    rep.repo["release"] = {"tag": rel.get("tag_name"), "published_at": rel.get("published_at"),
                           "url": rel.get("html_url"), "prerelease": rel.get("prerelease", False)}
    rep.add("info", "Releases", f"Neuestes Release {rel.get('tag_name')} vom {de_date(rel.get('published_at'))}"
            + (" (Vorabversion)" if rel.get("prerelease") else "") + f", {len(assets)} Dateien.")
    if rel_age is not None and rel_age < 3:
        rep.add("info", "Releases", f"Release ist erst {rel_age} Tage alt.",
                detail="Ganz frische Releases hat noch kaum jemand geprüft.")

    installers = [a for a in assets if INSTALLER_RE.search(a["name"]) and not CHECKSUM_RE.search(a["name"])]
    has_sums = any(CHECKSUM_RE.search(a["name"]) for a in assets)
    has_sigs = any(SIGNATURE_RE.search(a["name"]) for a in assets)
    uploaders = {(a.get("uploader") or {}).get("login") for a in installers}

    if installers:
        # Attestations: belegte Build-Herkunft (stärker als Prüfsummen)
        attested = 0
        for a in installers[:6]:
            dg = a.get("digest")
            if not dg:
                continue
            try:
                res = gh_api(f"repos/{full}/attestations/{dg}")
                if res and res.get("attestations"):
                    attested += 1
            except (NotFound, GhError):
                pass

        if has_sums:
            rep.add("ok", "Releases", "Prüfsummen liegen bei.")
        elif attested:
            rep.add("info", "Releases", "Keine Prüfsummen-Datei, aber die Build-Herkunft ist belegt (siehe unten). Das reicht.")
        else:
            rep.add("warn", "Releases", "Keine Prüfsummen im Release.",
                    detail="Man kann nicht nachprüfen, ob die Datei unterwegs verändert wurde.")
        if has_sigs:
            rep.add("ok", "Releases", "Signatur-Dateien liegen bei (z. B. Sigstore/GPG).")
        bot = "github-actions[bot]"
        humans = sorted(u for u in uploaders if u and u != bot)
        if uploaders == {bot}:
            rep.add("ok", "Releases", "Alle Dateien wurden automatisch von GitHub Actions hochgeladen.")
        elif bot in uploaders:
            rep.add("info", "Releases", f"Dateien teils von GitHub Actions, teils von Hand hochgeladen ({', '.join(humans)}).",
                    detail="Bei den Hand-Uploads lässt sich nicht nachprüfen, ob sie aus dem gezeigten Code gebaut wurden.")
        elif humans:
            rep.add("info", "Releases", f"Dateien wurden von Hand hochgeladen ({', '.join(humans)}), nicht von GitHub Actions.",
                    detail="Dann lässt sich nicht nachprüfen, ob die Datei wirklich aus dem gezeigten Code gebaut wurde.")

        if attested:
            rep.add("ok", "Releases", f"Build-Herkunft belegt (Attestation) für {attested} Datei(en).",
                    detail="Prüfbar mit: gh attestation verify <datei> --repo " + full)
    return installers


def vt_lookup(sha: str, key: str) -> dict | None:
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp).get("data", {}).get("attributes", {})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}
        raise


def check_virustotal(rep: Report, installers: list[dict]):
    key = os.environ.get("VT_API_KEY", "").strip()
    candidates = [a for a in installers if a.get("digest", "").startswith("sha256:")]
    # Dein Publikum nutzt Windows und Android: die zuerst, andere Systeme nur, wenn es nichts davon gibt
    relevant = [a for a in candidates if WINDOWS_RE.search(a["name"]) or ANDROID_RE.search(a["name"])]
    windows_first = sorted(relevant or candidates, key=lambda a: 0 if WINDOWS_RE.search(a["name"]) else 1)[:4]
    rep.links["virustotal"] = [{"file": a["name"], "url": f"https://www.virustotal.com/gui/file/{a['digest'][7:]}"} for a in windows_first]

    if not installers:
        return
    if not candidates:
        rep.add("info", "VirusTotal", "GitHub liefert für diese Dateien keine Prüfsumme. Datei bei Bedarf selbst auf virustotal.com prüfen.")
        return
    if not key:
        rep.add("info", "VirusTotal", "Kein VT_API_KEY gesetzt. Prüf die Dateien per Link (unten) selbst.")
        return

    any_unsigned_win = False
    for a in windows_first:
        sha = a["digest"][7:]
        try:
            attr = vt_lookup(sha, key)
        except Exception as e:  # Netzwerk, Limit, falscher Schlüssel
            rep.add("info", "VirusTotal", f"{a['name']}: Abfrage fehlgeschlagen ({e}).")
            continue
        if attr == {}:
            rep.add("warn", "VirusTotal", f"{a['name']}: VirusTotal kennt die Datei noch nicht.",
                    detail="Datei auf virustotal.com hochladen. Sie ist öffentlich, also unkritisch.")
            continue
        st = attr.get("last_analysis_stats", {})
        mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
        total = sum(st.values()) or 0
        sig = attr.get("signature_info") or {}
        signer = sig.get("signers") or sig.get("subject") or ""
        signed_txt = f" Signiert von: {signer}." if signer else ""
        if WINDOWS_RE.search(a["name"]) and a["name"].lower().endswith((".exe", ".msi")) and not signer:
            any_unsigned_win = True
        line = f"{a['name']}: {mal} von {total} Scannern melden Schadsoftware" + (f", {sus} verdächtig" if sus else "") + "." + signed_txt
        if mal >= 5:
            rep.add("bad", "VirusTotal", line, detail="Finger weg, bis das geklärt ist.")
        elif mal >= 1 or sus >= 2:
            rep.add("warn", "VirusTotal", line, detail="Bei unsignierten Hobby-Tools oft Fehlalarm. Prüf, welche Scanner es sind.")
        else:
            rep.add("ok", "VirusTotal", line)
    if any_unsigned_win:
        rep.hake("Nicht signiert, Windows warnt beim ersten Start.")


# ---------------------------------------------------------------- 4. Code-Scan

SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|webp|ico|icns|bmp|tiff?|psd|mp[34]|wav|ogg|webm|mov|avi|woff2?|ttf|otf|eot|pdf|lock|sum|map|svg|glb|gltf|fbx|obj|blend|bin|dat|pak|db|sqlite)$", re.I)
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "poetry.lock", "go.sum", "composer.lock", "gemfile.lock"}
BINARY_EXT = re.compile(r"\.(exe|dll|scr|sys|com|msi|jar|apk|so|dylib|node)$", re.I)
CODE_EXT = re.compile(r"\.(js|mjs|cjs|ts|tsx|jsx|py|ps1|psm1|bat|cmd|vbs|sh|cs|go|rs|java|kt|rb|php|lua|au3|ahk|c|cpp|h)$", re.I)
BINARY_OK = {"gradle-wrapper.jar", "maven-wrapper.jar"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|testdata|fixtures?)(/|$)|[A-Za-z]Tests?(/|\.)|\.(test|spec)\.", re.I)
PRIVATE_IP = re.compile(r"^(127\.|0\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)")

# (id, Stufe, Muster, Beschreibung, nur_in)
RULES = [
    ("remote-exec-ps", "warn",
     r"(?i)(irm|iwr|invoke-restmethod|invoke-webrequest|downloadstring|net\.webclient)[^\n]{0,200}\|\s*(iex|invoke-expression)\b|\b(iex|invoke-expression)\s*\(?\s*\(?\s*(new-object\s+net\.webclient|irm|iwr|invoke-restmethod|invoke-webrequest)",
     "Lädt Code aus dem Internet und führt ihn sofort aus (PowerShell-Einzeiler).", None),
    ("remote-exec-sh", "warn",
     r"(?i)\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b",
     "Lädt ein Skript aus dem Internet und führt es sofort aus (curl | sh).", None),
    ("encoded-ps", "bad",
     r"(?i)powershell(\.exe)?[^\n]{0,60}\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{24,}",
     "Versteckter, kodierter PowerShell-Befehl.", None),
    ("b64-exec", "bad",
     r"(?i)\b(eval|exec|function|invoke-expression|iex|assembly\]::load|reflection\.assembly)\s*\(?[^\n]{0,120}(frombase64string|b64decode|atob\(|base64)",
     "Führt versteckten (Base64-)Code aus.", CODE_EXT),
    ("discord-webhook", "bad",
     r"(?i)discord(app)?\.com/api/webhooks/\d+",
     "Discord-Webhook: typischer Weg, gestohlene Daten abzuschicken.", None),
    ("telegram-bot", "warn",
     r"(?i)api\.telegram\.org/bot",
     "Telegram-Bot-Schnittstelle: kann legitim sein, wird aber oft zum Abschicken von Daten genutzt.", CODE_EXT),
    ("paste-exfil", "warn",
     r"(?i)(pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|transfer\.sh|anonfiles\.|gofile\.io|file\.io/|ngrok\.io|ngrok-free\.app)",
     "Nutzt Paste- oder Upload-Dienste, über die oft Schadcode nachgeladen wird.", CODE_EXT),
    ("raw-ip", "warn",
     r"(?i)https?://((?:\d{1,3}\.){3}\d{1,3})(:\d+)?/",
     "Verbindet sich direkt mit einer IP-Adresse statt einer Domain.", CODE_EXT),
    ("browser-creds", "bad",
     r"(?i)(chrome|edge|brave|opera|yandex|chromium|user data)[^\n]{0,120}(login data|local state|web data|\bcookies\b)|(login data|local state|web data)[^\n]{0,120}(chrome|edge|brave|opera|chromium)",
     "Greift auf gespeicherte Browser-Passwörter oder Cookies zu.", CODE_EXT),
    ("dpapi", "warn",
     r"(?i)cryptunprotectdata|protecteddata\.unprotect",
     "Entschlüsselt geschützte Windows-Daten (wird zum Auslesen von Passwörtern benutzt).", CODE_EXT),
    ("wallets", "warn",
     r"(?i)wallet\.dat|\bexodus\b[^\n]{0,40}(wallet|appdata)|\belectrum\b[^\n]{0,40}wallet|nkbihfbeogaeaoehlefnkodbefgpgknn|telegram desktop[^\n]{0,40}tdata",
     "Sucht nach Krypto-Wallets oder Telegram-Sitzungen.", CODE_EXT),
    ("discord-token", "bad",
     r"(?i)discord[^\n]{0,80}(local storage|leveldb)",
     "Liest Discord-Anmeldedaten aus.", CODE_EXT),
    ("defender-off", "bad",
     r"(?i)add-mppreference[^\n]{0,80}-exclusion|set-mppreference[^\n]{0,80}-disable|disablerealtimemonitoring|disableantispyware",
     "Schaltet Windows Defender ab oder legt Ausnahmen an.", None),
    ("uac-bypass", "warn",
     r"(?i)\b(fodhelper|computerdefaults\.exe|sdclt\.exe)\b",
     "Bekannter Trick, um die Admin-Abfrage (UAC) zu umgehen.", CODE_EXT),
    ("autostart", "info",
     r"(?i)currentversion\\\\?run\b|schtasks(\.exe)?\s+/create|start menu\\\\?programs\\\\?startup",
     "Trägt sich in den Autostart ein. Bei Taskleisten-Tools normal.", CODE_EXT),
    ("npm-install-hook", "warn",
     r"\"(preinstall|postinstall|install)\"\s*:\s*\"",
     "Führt beim npm-Install automatisch Code aus.", re.compile(r"package\.json$", re.I)),
    ("setup-py-net", "warn",
     r"(?i)(urllib|requests\.get|subprocess|os\.system|exec\()",
     "setup.py führt beim Installieren Netzwerk- oder Systembefehle aus.", re.compile(r"(^|/)setup\.py$", re.I)),
    ("big-blob", "warn",
     r"[A-Za-z0-9+/]{4000,}={0,2}",
     "Großer kodierter Datenblock im Code (kann versteckten Code enthalten).", CODE_EXT),
]
COMPILED = [(rid, lvl, re.compile(pat), desc, only) for rid, lvl, pat, desc, only in RULES]
OBFUSCATED_JS = re.compile(r"_0x[0-9a-f]{4,6}")


def check_code(rep: Report, max_kb: int = 250_000):
    full = rep.repo["full_name"]
    if rep.repo.get("size_kb", 0) > max_kb:
        rep.add("info", "Code", f"Repo ist zu groß für den Schnell-Scan ({de_num(rep.repo['size_kb'] / 1024)} MB).")
        return
    try:
        data = gh_api(f"repos/{full}/tarball", raw=True, timeout=300)
    except (NotFound, GhError) as e:
        rep.add("info", "Code", f"Quellcode konnte nicht geladen werden ({e}).")
        return

    hits: dict[str, list] = {}
    binaries, scanned = [], 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for m in tar:
            if not m.isfile():
                continue
            path = m.name.split("/", 1)[1] if "/" in m.name else m.name
            base = path.rsplit("/", 1)[-1].lower()
            if BINARY_EXT.search(base):
                if base not in BINARY_OK:
                    binaries.append(path)
                continue
            if SKIP_EXT.search(base) or base in SKIP_NAMES or m.size > 1_500_000:
                continue
            f = tar.extractfile(m)
            if not f:
                continue
            raw = f.read()
            if b"\x00" in raw[:2048]:
                continue
            text = raw.decode("utf-8", "ignore")
            scanned += 1
            for rid, lvl, rx, desc, only in COMPILED:
                if only is not None and not only.search(path):
                    continue
                for mt in rx.finditer(text):
                    if rid == "raw-ip" and PRIVATE_IP.match(mt.group(1)):
                        continue
                    lst = hits.setdefault(rid, [])
                    if len(lst) < 8:
                        ln = text.count("\n", 0, mt.start()) + 1
                        line = text.splitlines()[ln - 1] if ln - 1 < len(text.splitlines()) else ""
                        lst.append((path, ln, line.strip()[:180]))
                    if len(lst) >= 8:
                        break
            if base.endswith((".js", ".mjs", ".cjs")) and len(OBFUSCATED_JS.findall(text)) > 60:
                hits.setdefault("obfuscated-js", []).append((path, 0, "viele _0x…-Namen"))

    rep.repo["files_scanned"] = scanned
    desc_by_id = {rid: (lvl, desc) for rid, lvl, _, desc, _ in COMPILED}
    desc_by_id["obfuscated-js"] = ("warn", "Verschleierter JavaScript-Code (typisch für versteckte Schadsoftware).")

    if not hits:
        rep.add("ok", "Code", f"{de_num(scanned)} Dateien durchsucht, keine typischen Warnzeichen gefunden.")
    for rid, lst in sorted(hits.items(), key=lambda kv: LEVEL_ORDER[desc_by_id[kv[0]][0]]):
        lvl, desc = desc_by_id[rid]
        docs_only = all(re.search(r"\.(md|txt|rst|html?)$", p, re.I) for p, _, _ in lst)
        ci_only = all(p.startswith(".github/") for p, _, _ in lst)
        test_only = all(TEST_PATH.search(p) for p, _, _ in lst)
        if docs_only and lvl != "bad":
            lvl = "info"
            desc += " (nur in der Anleitung)"
        elif ci_only and lvl != "bad":
            lvl = "info"
            desc += " (nur im Build-Skript auf GitHub, nicht im Programm)"
        elif test_only and lvl != "bad":
            lvl = "info"
            desc += " (nur in Testdateien)"
        p, ln, snip = lst[0]
        more = f" und {len(lst) - 1} weitere Stelle(n)" if len(lst) > 1 else ""
        rep.add(lvl, "Code", desc, detail=f"Fundstelle: {p}:{ln}{more}", file=p, line=ln, snippet=snip)
        if rid == "remote-exec-ps" and docs_only:
            rep.hake("Installation per PowerShell-Einzeiler: Der lädt Code aus dem Netz, vorher ansehen.")

    if binaries:
        shown = ", ".join(binaries[:4]) + (" …" if len(binaries) > 4 else "")
        rep.add("warn", "Code", f"{len(binaries)} fertige Programmdatei(en) direkt im Quellcode: {shown}",
                detail="Die kann niemand im Code nachprüfen.")


# ---------------------------------------------------------------- 5. Issues

def check_issues(rep: Report):
    full = rep.repo["full_name"]
    q = urllib.parse.quote(f"repo:{full} in:title virus OR malware OR trojan OR stealer OR antivirus")
    try:
        res = gh_api(f"search/issues?q={q}&per_page=5&sort=created&order=desc")
    except (NotFound, GhError):
        return
    n = (res or {}).get("total_count", 0)
    if n == 0:
        rep.add("ok", "Issues", "Niemand meldet in den Issues Virus oder Malware.")
        return
    titles = "; ".join(f"„{i['title'][:70]}“ ({'offen' if i['state'] == 'open' else 'geschlossen'})" for i in res["items"][:3])
    rep.add("warn", "Issues", f"{n} Issue(s) erwähnen Virus, Malware oder Antivirus. Lesen!",
            detail=titles)
    rep.links["issues"] = [i["html_url"] for i in res["items"][:5]]


# ---------------------------------------------------------------- 6. Trivy

def find_trivy() -> str | None:
    cands = [os.environ.get("TRIVY_PATH", ""), shutil.which("trivy") or "",
             os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "trivy", "trivy.exe")]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def check_trivy(rep: Report):
    exe = find_trivy()
    if not exe:
        rep.add("info", "Trivy", "Trivy nicht installiert, übersprungen.")
        return
    url = f"https://github.com/{rep.repo['full_name']}"
    try:
        r = subprocess.run([exe, "repo", "--scanners", "vuln,secret", "--format", "json", "--quiet",
                            "--timeout", "15m", url], capture_output=True, timeout=1200)
    except subprocess.TimeoutExpired:
        rep.add("info", "Trivy", "Trivy hat zu lange gebraucht, übersprungen.")
        return
    if r.returncode != 0:
        rep.add("info", "Trivy", "Trivy-Scan fehlgeschlagen: " + r.stderr.decode("utf-8", "replace").strip()[-200:])
        return
    data = json.loads(r.stdout.decode("utf-8", "replace") or "{}")
    sev: dict[str, int] = {}
    secrets = []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            sev[v.get("Severity", "UNKNOWN")] = sev.get(v.get("Severity", "UNKNOWN"), 0) + 1
        for s in res.get("Secrets") or []:
            secrets.append(f"{res.get('Target')}: {s.get('Title')}")
    crit, high = sev.get("CRITICAL", 0), sev.get("HIGH", 0)
    if crit or high:
        rep.add("warn", "Trivy", f"Bekannte Sicherheitslücken in verwendeten Bibliotheken: {crit} kritisch, {high} hoch.",
                detail="Das ist keine Schadsoftware, aber veraltete Bausteine mit bekannten Lücken.")
    else:
        rep.add("ok", "Trivy", "Keine kritischen oder hohen bekannten Lücken in den Bibliotheken.")
    if secrets:
        rep.add("warn", "Trivy", f"{len(secrets)} Geheimnis(se) im Code, z. B. Schlüssel oder Tokens.",
                detail="; ".join(secrets[:3]))


# ---------------------------------------------------------------- Ausgabe

def finalize(rep: Report):
    levels = [f.level for f in rep.findings]
    if "bad" in levels:
        rep.verdict, rep.verdict_text = "ROT", "Nicht zeigen, bevor die roten Punkte geklärt sind."
    elif "warn" in levels:
        rep.verdict, rep.verdict_text = "GELB", "Zeigen geht, aber die Haken im Video nennen."
    else:
        rep.verdict, rep.verdict_text = "GRÜN", "Keine Auffälligkeiten gefunden."


def print_report(rep: Report):
    r = rep.repo
    icon = {"ROT": "🔴", "GELB": "🟡", "GRÜN": "🟢"}.get(rep.verdict, "⚪")
    print()
    print(f"Repo-Check: {r.get('full_name', '?')}   ({NOW.astimezone().strftime('%d.%m.%Y %H:%M')})")
    if r.get("url"):
        print(r["url"])
        bits = [f"⭐ {de_num(r.get('stars', 0))}", f"Forks {de_num(r.get('forks', 0))}",
                f"Mitwirkende {r.get('contributors', '?')}", f"Lizenz {r.get('license') or '–'}"]
        print("   ".join(bits))
    print()
    print(f"GESAMT: {icon} {rep.verdict}: {rep.verdict_text}")
    area = None
    for f in sorted(rep.findings, key=lambda f: (["Herkunft", "Sterne", "Releases", "VirusTotal", "Code", "Issues", "Trivy"].index(f.area), LEVEL_ORDER[f.level])):
        if f.area != area:
            area = f.area
            print(f"\n{area}")
        print(f"  {LEVEL_ICON[f.level]} {f.text}")
        if f.detail:
            print(f"     {f.detail}")
        if f.snippet:
            print(f"     › {f.snippet}")
    if rep.links.get("virustotal"):
        print("\nVirusTotal-Links (Prüfsumme, nichts wird hochgeladen):")
        for l in rep.links["virustotal"]:
            print(f"  {l['file']}: {l['url']}")
    if rep.haken:
        print("\nHaken-Vorschlag fürs Video / tools.js:")
        print("  " + " ".join(rep.haken))
    print()


def main():
    ap = argparse.ArgumentParser(description="Sicherheits-Schnellcheck für ein GitHub-Repo")
    ap.add_argument("repo", help="https://github.com/owner/repo oder owner/repo")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-stars", action="store_true")
    ap.add_argument("--no-code", action="store_true")
    ap.add_argument("--no-trivy", action="store_true")
    args = ap.parse_args()

    owner, name = parse_repo(args.repo)
    rep = Report()
    steps = []
    if check_origin(rep, owner, name) is not None:
        steps = [
            ("Sterne", (lambda: None) if args.no_stars else (lambda: check_stars(rep))),
            ("Releases", lambda: check_virustotal(rep, check_releases(rep))),
            ("Code", (lambda: None) if args.no_code else (lambda: check_code(rep))),
            ("Issues", lambda: check_issues(rep)),
            ("Trivy", (lambda: None) if args.no_trivy else (lambda: check_trivy(rep))),
        ]
    for label, fn in steps:
        if not args.json:
            print(f"… {label}", file=sys.stderr, flush=True)
        try:
            fn()
        except GhError as e:
            rep.add("info", label if label in ("Sterne", "Releases", "Code", "Issues", "Trivy") else "Herkunft",
                    f"Schritt übersprungen: {e}")
    finalize(rep)

    if args.json:
        out = asdict(rep)
        out["findings"] = sorted(out["findings"], key=lambda f: LEVEL_ORDER[f["level"]])
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print_report(rep)
    sys.exit({"ROT": 2, "GELB": 1}.get(rep.verdict, 0))


if __name__ == "__main__":
    main()
