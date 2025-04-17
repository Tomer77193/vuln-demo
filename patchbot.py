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

for alert in alerts:
    pkg = alert["dependency"]["package"]["name"]
    adv = alert["security_advisory"]
    # at the top of your loop, after `adv = alert["security_advisory"]`
    manifest = alert["dependency"]["manifest_path"]  # e.g. "examples/celery/requirements.txt"

    # extract the safe version as before
    safe = extract_safe_version(adv)
    if not safe:
        print(f"⚠️  Couldn’t find a patched version for {pkg}, skipping")
        continue

    print(f"Fixing {pkg} → {safe}")
    
    # now run your bump+commit+PR steps *inside* this loop
    # 1) update requirements.txt
    # 2) git checkout -b patchbot/{pkg}-{safe}
    # 3) git config … (the CI identity)
    # 4) git add/commit/push
    # 5) create_pull(...)


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
from pathlib import Path
import json

# 2. Update the right manifest
path = Path(manifest)  # e.g. "examples/celery/requirements.txt" or "package.json"

if not path.exists():
    print(f"⚠️  Manifest {manifest!r} not found, skipping")
    continue

if manifest.endswith(".txt"):
    # pip‐style requirements
    with path.open("r+", encoding="utf-8") as f:
        text = f.read()
        text = re.sub(rf"{pkg}==[0-9A-Za-z.\-]+", f"{pkg}=={safe}", text)
        f.seek(0); f.write(text); f.truncate()

elif manifest.endswith(".json"):
    # npm‐style package.json
    data = json.loads(path.read_text(encoding="utf-8"))
    changed = False
    for section in ("dependencies", "devDependencies"):
        if section in data and pkg in data[section]:
            data[section][pkg] = safe
            changed = True
    if not changed:
        print(f"⚠️  {pkg} not found in {manifest}, skipping")
        continue
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

else:
    # other types (e.g. pyproject.toml) could go here later
    print(f"⚠️  Unknown manifest type: {manifest}, skipping")
    continue


# 3. Commit & push a new branch
branch = f"patchbot/{pkg}-{safe}"
subprocess.check_call(["git", "checkout", "-B", branch])

# tell Git who the CI bot is  (must be BEFORE the commit)
subprocess.check_call(["git", "config", "--global",
                       "user.email", "patchbot@users.noreply.github.com"])
subprocess.check_call(["git", "config", "--global",
                       "user.name",  "Patch‑Bot"])

subprocess.check_call(["git", "add", "requirements.txt"])
subprocess.check_call(["git", "commit", "-m", f"chore: bump {pkg} to {safe}"])
subprocess.check_call(["git", "push", "-u", "origin", branch])
# 4. Open the pull request
pr = rep.create_pull(
    title=f"chore: bump {pkg} to {safe}",
    body="Automated fix by **Patch‑Bot**",
    head=branch,
    base="main"
)
