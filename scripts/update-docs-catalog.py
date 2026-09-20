"""Generate script-free release and contributor pages from public GitHub metadata."""

from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from urllib.request import Request, urlopen

REPO = "tarsolution/tarvaultsync"
ROOT = Path(__file__).resolve().parents[1]


def fetch(path):
    request = Request("https://api.github.com/" + path,
                      headers={"Accept": "application/vnd.github+json",
                               "User-Agent": "TAR-Vault-Sync-docs"})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def listing(endpoint):
    result = []
    page = 1
    while True:
        batch = fetch(f"repos/{REPO}/{endpoint}?per_page=100&page={page}")
        result.extend(batch)
        if len(batch) < 100:
            return result
        page += 1


def link(url, label):
    if not url.startswith("https://github.com/"):
        raise ValueError("Expected a public GitHub URL")
    return f'<a href="{escape(url, quote=True)}">{escape(label)}</a>'


def page(title, content, date):
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TAR Vault Sync · {title}</title><link rel="stylesheet" href="site.css">
<link rel="icon" type="image/png" href="assets/mark.png">
<script defer src="assets/analytics.js"></script>
<meta property="og:type" content="website">
<meta property="og:site_name" content="TAR Vault Sync">
<meta property="og:title" content="TAR Vault Sync">
<meta property="og:description" content="Local-first encrypted vaults and secure secret synchronization.">
<meta property="og:image" content="https://tarvault.tarsolution.com/assets/mark.png">
<meta property="og:image:alt" content="TAR Vault Sync logo">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="TAR Vault Sync">
<meta name="twitter:description" content="Local-first encrypted vaults and secure secret synchronization.">
<meta name="twitter:image" content="https://tarvault.tarsolution.com/assets/mark.png">
<meta name="twitter:image:alt" content="TAR Vault Sync logo">
</head>
<body><aside><a class="brand" href="index.html"><img src="assets/mark.png" alt=""><span>TAR<small>VAULT SYNC</small></span></a><p class="eyebrow">PROJECT</p><nav aria-label="Documentation"><a href="index.html">Desktop guide</a><a href="releases.html">Releases &amp; archive</a><a href="credits.html">Credits &amp; contributors</a></nav><a class="repo" href="https://github.com/{REPO}">View source on GitHub ↗</a><div class="credits"><a href="https://tarsolution.com/">A TAR Solution project</a><a href="https://fmarslan.com/">Developed by fmarslan.com</a><a href="credits.html">Credits &amp; contributors</a></div></aside>
<main><header><p class="eyebrow">TAR VAULT SYNC</p><h1>{title}</h1></header>{content}<footer>GitHub metadata snapshot: {date}. This static page makes no browser API requests.</footer></main></body></html>
'''


def release_card(release):
    name = release.get("name") or release["tag_name"]
    status = "Pre-release" if release.get("prerelease") else "Stable release"
    return (f'<article class="release-card"><h3>{link(release["html_url"], name)}</h3>'
            f'<p>{status} · {escape(release["tag_name"])} · '
            f'{escape(release["published_at"][:10])}</p><p>'
            f'{link(release["html_url"], "Release notes, downloads & checksums on GitHub")}'
            '</p></article>')


def releases_content(releases):
    published = sorted((r for r in releases if not r.get("draft") and r.get("published_at")),
                       key=lambda r: r["published_at"], reverse=True)
    latest = next((r for r in published if not r.get("prerelease")), None)
    content = '<p>Published GitHub releases only. CI artifacts are not releases.</p><section id="latest"><h2>Latest stable release</h2>'
    content += release_card(latest) if latest else '<p>No stable release has been published yet.</p>'
    content += '</section><section id="archive"><h2>Release archive</h2><p>Newest first; pre-releases are explicitly labelled.</p>'
    archive = [r for r in published if r is not latest]
    content += ''.join(map(release_card, archive)) if archive else '<p>No archived releases yet.</p>'
    return content + f'</section><p>{link(f"https://github.com/{REPO}/releases", "View the live release catalogue on GitHub")}</p>'


def main():
    # Fetch everything before replacing either page. Network failures fail the build.
    releases = listing("releases")
    contributors = listing("contributors")
    people, bots = [], []
    for contributor in contributors:
        login = contributor["login"]
        profile = fetch("users/" + login)
        name = profile.get("name") or login
        item = '<li>' + link(contributor["html_url"], f'{name} (@{login})') + '</li>'
        (bots if contributor.get("type") == "Bot" else people).append(item)
    credits = '<p>A project of the <a href="https://github.com/tarsolution">TAR Solution organization</a>, developed by <a href="https://fmarslan.com/">fmarslan.com</a>.</p><section><h2>Contributors</h2><p>Public GitHub commit contributors, using public profile names where available. This list does not imply ownership and may omit non-code or unattributed contributions.</p>'
    credits += '<ul>' + ''.join(people) + '</ul>' if people else '<p>No public contributors listed yet.</p>'
    credits += '</section>'
    if bots:
        credits += '<section><h2>Automation</h2><ul>' + ''.join(bots) + '</ul></section>'
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for filename, title, content in [("releases.html", "Releases", releases_content(releases)),
                                     ("credits.html", "Credits &amp; contributors", credits)]:
        (ROOT / "docs" / filename).write_text(page(title, content, date), encoding="utf-8")


if __name__ == "__main__":
    main()
