# --- patchbot.py (robust) ---------------------------------------
import os, re, subprocess, requests
from github import Github

OWNER = "Tomer77193"          # your GitHub username
REPO  = "vuln-demo"           # repo name

GH_TOKEN = os.environ["GH_TOKEN"]          # set in CMD with:  set GH_TOKEN=ghp_...
g   = Github(GH_TOKEN)
rep = g.get_repo(f"{OWNER}/{REPO}")

# ---------------------------------------------------------------
alerts = requests.get(
    f"https://api.github.com/repos/{OWNER}/{REPO}/dependabot/alerts",
    headers={
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json"
    }).json()

if not alerts:
    raise SystemExit("No open Dependabot alerts found")

alert = alerts[0]
pkg   = alert["dependency"]["package"]["name"]
adv   = alert["security_advisory"]

def extract_safe_version(advisory: dict) -> str | None:
    # 1) Preferred: top‑level first_patched_version
    fpv = advisory.get("first_patched_version", {})
    if isinstance(fpv, dict) and fpv.get("identifier"):
        return fpv["identifier"]

    # 2) Nested vulnerabilities list
    for vuln in advisory.get("vulnerabilities", []):
        id_ = vuln.get("first_patched_version", {}).get("identifier")
        if id_:
            return id_

    # 3) Parse from vulnerable_version_range / vulnerable_versions
    rng = (advisory.get("vulnerable_versions") or
           advisory.get("vulnerable_version_range") or "")
    match = re.search(r"<\s*([0-9A-Za-z][0-9A-Za-z.\-]*)", rng)
    if match:
        return match.group(1)

    return None

safe = extract_safe_version(adv)
if not safe:
    raise ValueError("Could not find safe version in advisory JSON")

print(f"Need to bump {pkg} → {safe}")
# ---------------------------------------------------------------

# 2. Update requirements.txt
with open("requirements.txt", "r+", encoding="utf-8") as f:
    text = f.read()
    text = re.sub(rf"{pkg}==[0-9A-Za-z.\-]+", f"{pkg}=={safe}", text)
    f.seek(0); f.write(text); f.truncate()

# 3. Commit & push a new branch
branch = f"patchbot/{pkg}-{safe}"
subprocess.check_call(["git", "checkout", "-B", branch])
subprocess.check_call(["git", "add", "requirements.txt"])
subprocess.check_call(["git", "commit", "-m", f"chore: bump {pkg} to {safe}"])
subprocess.check_call(["git", "push", "-u", "origin", branch])

# 4. Open the pull request
pr = rep.create_pull
