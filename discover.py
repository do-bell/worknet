"""Discover candidate free subscription URLs from GitHub search.

This is a candidate finder only: it writes discovered_sources.txt, which
merge.py also reads. If discovery fails (rate limit, network, etc.) it
must not break the main merge job, so every failure is caught and the
existing discovered file is left untouched when possible.
"""
import base64
import json
import os
import re
import urllib.request


def get_json(url, headers):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def main():
    token = os.environ.get("GH_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    found = []
    try:
        search_url = (
            "https://api.github.com/search/repositories"
            "?q=free+nodes&sort=updated&order=desc&per_page=20"
        )
        data = get_json(search_url, headers)
        for item in data.get("items", []):
            if item.get("fork"):
                continue
            if item.get("stargazers_count", 0) < 20:
                continue
            try:
                readme = get_json(
                    f"https://api.github.com/repos/{item['full_name']}/readme",
                    headers,
                )
                content = base64.b64decode(readme["content"]).decode(
                    "utf-8", errors="ignore"
                )
                links = re.findall(
                    r"https://raw\.githubusercontent\.com/[^\s\)\"']+\.(?:txt|yaml|yml)",
                    content,
                )
                found.extend(links)
            except Exception as e:
                print(f"SKIP {item.get('full_name')}: {e}")
    except Exception as e:
        print(f"Discovery search failed, keeping old candidates: {e}")
        return

    unique = sorted(set(found))
    with open("discovered_sources.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unique))
    print(f"Found: {len(unique)} candidate subscription URLs")


if __name__ == "__main__":
    main()
