import base64
import json
import socket
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor


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


def _b64_decode(text):
    text = text.strip()
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")


def parse_host_port(line):
    """Return (host, port) or None if the line cannot be parsed.

    Returning None means 'keep the node': a parser failure must never
    delete a node by itself, it only skips the TCP test for that line.
    """
    try:
        line = line.strip()
        if line.startswith("vmess://"):
            raw = line[len("vmess://"):].split("#")[0].split("?")[0]
            data = json.loads(_b64_decode(raw))
            host = data.get("add")
            port = data.get("port")
            if host and port:
                return host, int(port)
            return None
        if line.startswith("ss://"):
            rest = line[len("ss://"):].split("#")[0]
            # ss://method:password@host:port  or
            # ss://base64(method:password)@host:port  or
            # ss://base64(method:password@host:port)
            if "@" in rest:
                hostport = rest.rsplit("@", 1)[1]
            else:
                decoded = _b64_decode(rest)
                if "@" not in decoded:
                    return None
                hostport = decoded.rsplit("@", 1)[1]
            hostport = hostport.split("?")[0].split("/")[0]
            if ":" not in hostport:
                return None
            host, port_str = hostport.rsplit(":", 1)
            host = host.strip("[]")
            if host and port_str.isdigit():
                return host, int(port_str)
            return None
        parsed = urllib.parse.urlparse(line)
        host = parsed.hostname
        port = parsed.port
        if host and port:
            return host, port
        return None
    except Exception:
        return None


def tcp_ok(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def tcp_filter(nodes):
    """Keep nodes whose TCP port is reachable (with one retry).

    This filters out definitely-dead servers: DNS failure, port closed,
    server offline. It does NOT prove a node works from China, or that
    its proxy authentication works - those still need a phone test.
    Nodes that cannot be parsed are kept, not dropped.
    """
    def check(line):
        parsed = parse_host_port(line)
        if parsed is None:
            return line, True, "unparsed-kept"
        host, port = parsed
        if tcp_ok(host, port, timeout=4):
            return line, True, "ok"
        # One retry for flaky free servers.
        if tcp_ok(host, port, timeout=4):
            return line, True, "ok-retry"
        return line, False, "tcp-failed"

    kept = []
    dropped = 0
    unparsed = 0
    with ThreadPoolExecutor(max_workers=50) as executor:
        for line, ok, status in executor.map(check, nodes):
            if ok:
                kept.append(line)
                if status == "unparsed-kept":
                    unparsed += 1
            else:
                dropped += 1
    print(f"TCP test: total {len(nodes)}, kept {len(kept)}, "
          f"dropped {dropped}, unparsed-kept {unparsed}")
    return kept


def main():
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
            print(f"OK {url} -> +{len(nodes) - count_before} nodes, "
                  f"total {len(nodes)}")
        except Exception as e:
            print(f"SKIP {url}: {e}")

    print(f"Before TCP test: {len(nodes)} nodes")
    nodes = tcp_filter(nodes)

    with open("nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(nodes))
    with open("sub", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(nodes).encode()).decode())
    print(f"Done: {len(nodes)} nodes")


if __name__ == "__main__":
    main()
