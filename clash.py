"""Generate clash.yaml from nodes.txt (worknet).

Reads nodes.txt (one vmess:// / vless:// / trojan:// / ss:// URI per line,
as written by merge.py) and writes clash.yaml with:
  mixed-port / mode / log-level (top-level, so the file is a complete
  Clash/Mihomo config, not just a proxy list)
  proxies:        one entry per parseable node (deduped by name)
  proxy-groups:   "手动选择" (select) + "自动选择" (url-test, 300s)
  rules:          private IP ranges DIRECT, everything else through
                  手动选择. No GEOIP rule on purpose: GEOIP needs an
                  MMDB download, and if that download fails Mihomo
                  refuses to start at all; with IP-CIDR rules the file
                  validates and starts even offline.

Reality is handled, not dropped: a vless/trojan/vmess node with
security=reality becomes tls + reality-opts {public-key, short-id},
plus servername/fingerprint/flow when present. Without those fields
every current node (all VLESS Reality) would parse as YAML but fail
to connect, so a node missing its Reality public key is skipped
and counted instead of emitted broken.

Unsupported schemes (ssr/hysteria/hysteria2/tuic) are skipped and counted,
never silently renamed. Unparseable lines are skipped and counted.
"""
import base64
import json
import urllib.parse


def _b64_decode(text):
    text = text.strip()
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")


def _name(raw, fallback):
    name = urllib.parse.unquote(raw or "").strip() or fallback
    return name


def _first(q, key):
    v = q.get(key)
    return v[0] if v else None


def _apply_tls(p, q):
    """security=tls or security=reality -> tls, servername, fingerprint,
    and reality-opts when applicable. Returns False if Reality lacks
    its public key (node cannot work)."""
    sec = _first(q, "security") or _first(q, "tls")
    if sec not in ("tls", "reality"):
        return True
    p["tls"] = True
    if _first(q, "sni"):
        p["servername"] = _first(q, "sni")
    if _first(q, "fp"):
        p["fingerprint"] = _first(q, "fp")
    if _first(q, "alpn"):
        p["alpn"] = [a.strip() for a in _first(q, "alpn").split(",") if a.strip()]
    if sec == "reality":
        pbk = _first(q, "pbk")
        if not pbk:
            return False
        p["reality-opts"] = {
            "public-key": pbk,
            "short-id": _first(q, "sid") or "",
        }
    return True


def _apply_transport(p, q):
    net = _first(q, "type") or "tcp"
    if net == "ws":
        p["network"] = "ws"
        opts = {}
        if _first(q, "path"):
            opts["path"] = _first(q, "path")
        if _first(q, "host"):
            opts["headers"] = {"Host": _first(q, "host")}
        if _first(q, "ed"):
            opts["max-early-data"] = int(_first(q, "ed"))
            opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
        if opts:
            p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        opts = {}
        if _first(q, "serviceName"):
            opts["grpc-service-name"] = _first(q, "serviceName")
        if opts:
            p["grpc-opts"] = opts
    # tcp is the default: no network field needed.


def parse_vmess(line, idx):
    try:
        data = json.loads(_b64_decode(line[len("vmess://"):].split("#")[0]))
    except Exception:
        return None
    host, port = data.get("add"), data.get("port")
    if not host or not port:
        return None
    p = {
        "name": _name(data.get("ps"), f"vmess-{idx}"),
        "type": "vmess",
        "server": host,
        "port": int(port),
        "uuid": data.get("id", ""),
        "alterId": int(data.get("aid") or 0),
        "cipher": data.get("scy") or "auto",
    }
    if data.get("tls") in ("tls", "1", 1):
        p["tls"] = True
        if data.get("sni"):
            p["servername"] = data["sni"]
        if data.get("fp"):
            p["fingerprint"] = data["fp"]
        if data.get("alpn"):
            p["alpn"] = [a.strip() for a in str(data["alpn"]).split(",") if a.strip()]
    net = data.get("net")
    if net == "ws":
        p["network"] = "ws"
        opts = {}
        if data.get("path"):
            opts["path"] = data["path"]
        if data.get("host"):
            opts["headers"] = {"Host": data["host"]}
        if opts:
            p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        opts = {}
        if data.get("path"):
            opts["grpc-service-name"] = data["path"]
        if opts:
            p["grpc-opts"] = opts
    return p


def parse_vless_trojan(line, idx):
    scheme = line.split("://", 1)[0]
    u = urllib.parse.urlparse(line)
    if not u.hostname or not u.port:
        return None
    p = {
        "name": _name(u.fragment, f"{scheme}-{idx}"),
        "type": scheme,
        "server": u.hostname,
        "port": u.port,
    }
    if scheme == "vless":
        p["uuid"] = urllib.parse.unquote(u.username or "")
        if _first(urllib.parse.parse_qs(u.query), "flow"):
            p["flow"] = _first(urllib.parse.parse_qs(u.query), "flow")
    else:
        p["password"] = urllib.parse.unquote(u.username or "")
    q = urllib.parse.parse_qs(u.query)
    if not _apply_tls(p, q):
        return None
    _apply_transport(p, q)
    return p


def parse_ss(line, idx):
    rest = line[len("ss://"):]
    name = ""
    if "#" in rest:
        rest, name = rest.split("#", 1)
    if "?" in rest and "plugin=" in rest:
        return None  # plugin (obfs etc.) nodes are not emitted as plain ss
    try:
        if "@" in rest:
            userinfo, hostport = rest.rsplit("@", 1)
            try:
                userinfo = _b64_decode(userinfo)
            except Exception:
                pass
        else:
            userinfo_hostport = _b64_decode(rest)
            userinfo, hostport = userinfo_hostport.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        return {
            "name": _name(name, f"ss-{idx}"),
            "type": "ss",
            "server": host.strip("[]"),
            "port": int(port),
            "cipher": method,
            "password": password,
        }
    except Exception:
        return None


PARSERS = {"vmess://": parse_vmess, "vless://": parse_vless_trojan,
           "trojan://": parse_vless_trojan, "ss://": parse_ss}


def convert(lines):
    proxies, seen, skipped, unsupported = [], set(), 0, 0
    for idx, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        parser = next((fn for pfx, fn in PARSERS.items()
                       if line.startswith(pfx)), None)
        if parser is None:
            unsupported += 1
            continue
        proxy = parser(line, idx)
        if proxy is None or not proxy.get("server"):
            skipped += 1
            continue
        name = proxy["name"]
        if name in seen:  # keep first, rename later duplicates
            base, n = name, 2
            while f"{base}-{n}" in seen:
                n += 1
            proxy["name"] = f"{base}-{n}"
        seen.add(proxy["name"])
        proxies.append(proxy)
    return proxies, skipped, unsupported


def yaml_str(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if any(c in s for c in ":#{}[]&*!|>'\"%@`") or s != s.strip() or not s:
        return json.dumps(s, ensure_ascii=False)
    return s


def _dump_value(out, key, v, indent):
    pad = " " * indent
    if isinstance(v, dict):
        out.append(f"{pad}{key}:")
        for k2, v2 in v.items():
            _dump_value(out, k2, v2, indent + 2)
    elif isinstance(v, list):
        out.append(f"{pad}{key}: [{', '.join(yaml_str(x) for x in v)}]")
    else:
        out.append(f"{pad}{key}: {yaml_str(v)}")


def main():
    with open("nodes.txt", encoding="utf-8") as f:
        lines = f.read().splitlines()
    proxies, skipped, unsupported = convert(lines)
    out = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        "unified-delay: true",
        "tcp-concurrent: true",
        "",
        "proxies:",
    ]
    for p in proxies:
        out.append(f"  - name: {yaml_str(p['name'])}")
        for k, v in p.items():
            if k == "name":
                continue
            _dump_value(out, k, v, 4)
    names = [p["name"] for p in proxies]
    out += [
        "",
        "proxy-groups:",
        "  - name: 手动选择",
        "    type: select",
        "    proxies:",
    ]
    out += [f"      - {yaml_str(n)}" for n in names]
    out += [
        "  - name: 自动选择",
        "    type: url-test",
        "    url: http://www.gstatic.com/generate_204",
        "    interval: 300",
        "    proxies:",
    ]
    out += [f"      - {yaml_str(n)}" for n in names]
    out += [
        "",
        "rules:",
        "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "  - MATCH,手动选择",
        "",
    ]
    with open("clash.yaml", "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print(f"proxies={len(proxies)} skipped={skipped} "
          f"unsupported={unsupported} total={len(lines)}")


if __name__ == "__main__":
    main()
