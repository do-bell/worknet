import base64
import urllib.request


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", errors="ignore").strip()


def decode_maybe(text):
    text = text.strip()
    if "://" in text:
        return text
    # Try base64 (subscription links are often a base64 blob).
    try:
        padded = text + "=" * (-len(text) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        return text


def read_sources():
    sources = []
    for filename in ("sources.txt", "discovered_sources.txt"):
        try:
            with open(filename, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        sources.append(line)
        except FileNotFoundError:
            pass
    return sources


PROTOCOLS = (
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
    "ssr://",
    "hysteria://",
    "hysteria2://",
    "tuic://",
)

nodes = []
seen = set()
for url in read_sources():
    try:
        decoded = decode_maybe(fetch(url))
        count_before = len(nodes)
        for line in decoded.splitlines():
            line = line.strip()
            if line.startswith(PROTOCOLS) and line not in seen:
                seen.add(line)
                nodes.append(line)
        print(f"OK {url} -> +{len(nodes) - count_before} nodes, total {len(nodes)}")
    except Exception as e:
        print(f"SKIP {url}: {e}")

with open("nodes.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(nodes))
with open("sub", "w", encoding="utf-8") as f:
    f.write(base64.b64encode("\n".join(nodes).encode()).decode())
print(f"Done: {len(nodes)} nodes")
