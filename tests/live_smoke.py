"""Opt-in, networked calibration run. Not part of the unit tests.

    python tests/live_smoke.py                 # whole corpus, no VirusTotal, no Trivy
    python tests/live_smoke.py --vt            # with VirusTotal (needs VT_API_KEY; waits 65 s between repos)
    python tests/live_smoke.py owner/repo ...  # only these repos

Prints repo -> expected -> verdict -> score -> GitHub requests (core/search) -> top reasons.
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from generate_checks_md import load_engine  # noqa: E402

rc = load_engine()

# (repo, expected verdict)
CORPUS = [
    ("microsoft/PowerToys", "green"), ("localsend/localsend", "green"), ("upscayl/upscayl", "green"),
    ("chidiwilliams/buzz", "green"), ("yt-dlp/yt-dlp", "green"),
    ("BurntSushi/ripgrep", "green"),          # Rust CLI
    ("junegunn/fzf", "green"),                # Go tool
    ("marktext/marktext", "green"),           # Electron app
    ("psf/requests", "green"),                # Python package
    ("TeamNewPipe/NewPipe", "green"),         # Android app
    ("keepassxreboot/keepassxc", "green"),    # password manager: credential-adjacent code
    ("NVIDIA/garak", "green"),                # LLM security scanner: prompt-injection text everywhere
    ("ersinkoc/phonebox", "green/yellow"), ("KnifeLemon/Filee", "green/yellow"),
    ("net-merge/net-merge", "green/yellow"), ("storytold/photocraft", "green/yellow"),
    ("krisgfx9/Wireless-Device-Battery-Monitor", "unknown"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repos", nargs="*")
    ap.add_argument("--vt", action="store_true")
    ap.add_argument("--lang", default="en")
    a = ap.parse_args()
    corpus = [(r, "?") for r in a.repos] or CORPUS
    opts = argparse.Namespace(no_code=False, no_stars=False, no_vt=not a.vt, no_trivy=True, no_scorecard=False)
    token = rc.resolve_token()
    print(f"{'repo':42} {'expected':13} {'verdict':8} {'score':>5} {'req c/s':>8}  top reasons")
    for i, (repo, expected) in enumerate(corpus):
        if a.vt and i:
            time.sleep(65)
        owner, name = rc.parse_repo(repo)
        rep = rc.Report(owner, name, a.lang)
        started = time.monotonic()
        rc.run_all(rep, rc.GitHub(token), opts)
        top = [f"{f.id}(+{f.weight})" for f in sorted(rep.findings, key=lambda f: -f.weight) if f.weight > 0][:4]
        caps = ",".join(c.split(".", 1)[1] for c in rep.caps)
        skipped = ",".join(f"{c}:{r}" for c, r in rep.skipped if r != "disabled")
        req = rep.requests if hasattr(rep, "requests") else {"core": 0, "search": 0}
        print(f"{repo:42} {expected:13} {rep.verdict:8} {rep.score:5} {req['core']:>4}/{req['search']:<3}  "
              f"{'; '.join(top) or '-'}" + (f"  caps=[{caps}]" if caps else "") + (f"  skipped=[{skipped}]" if skipped else "")
              + f"  ({time.monotonic() - started:.0f}s)", flush=True)


if __name__ == "__main__":
    sys.exit(main())
