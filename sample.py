"""Generate a realistic mixed-format log of N lines."""
import json
import random
import sys
from datetime import datetime, timedelta

n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
seed = int(sys.argv[2]) if len(sys.argv) > 2 else 42
rng = random.Random(seed)

REAL_PATHS = [
    ("/", 0.10), ("/index.html", 0.06), ("/about", 0.03), ("/pricing", 0.04),
    ("/blog/using.gitlab-ci", 0.02), ("/docs/.environment-setup", 0.01),
    ("/api/users", 0.10), ("/api/orders", 0.07), ("/api/checkout", 0.05),
    ("/static/app.js", 0.08), ("/static/style.css", 0.07),
    ("/dashboard", 0.05), ("/login", 0.04), ("/search?q=widgets", 0.03),
]
DEAD_PATHS = ["/old-pricing", "/team/jsmith", "/downloads/v1/manual.pdf",
              "/blog/2019/moved-post", "/favicon.ico"]
PROBE_PATHS = ["/.env", "/.env.production", "/.git/config", "/wp-login.php",
               "/wp-admin/setup-config.php", "/phpmyadmin/index.php",
               "/admin/config/db.yml", "/.aws/credentials", "/xmlrpc.php",
               "/server-status", "/.ssh/id_rsa"]

NORMAL_IPS = [f"203.0.113.{i}" for i in range(10, 40)]
SCANNER_IPS = ["198.51.100.9", "198.51.100.77", "192.0.2.203"]
V6_IPS = ["2001:db8:1:2::5", "2001:db8:abcd:1::99"]

AGENTS = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
          "curl/8.4.0", "python-requests/2.31.0", "Googlebot/2.1"]

start = datetime(2026, 7, 26, 8, 0, 0)


def weighted_path():
    r, acc = rng.random(), 0.0
    for path, w in REAL_PATHS:
        acc += w
        if r < acc:
            return path
    return "/"


def latency(path, status):
    if status >= 500:
        return rng.randint(1500, 8000)
    if path.startswith("/api/"):
        return int(rng.lognormvariate(4.4, 0.8))
    if path.startswith("/static/"):
        return rng.randint(2, 25)
    return int(rng.lognormvariate(3.9, 0.7))


def pick_status(is_probe, path):
    if is_probe:
        # Most probes bounce; a couple find something.
        return rng.choices([404, 403, 200], weights=[80, 14, 6])[0]
    if path in DEAD_PATHS:
        return 404
    return rng.choices([200, 200, 200, 304, 301, 401, 429, 500, 502, 503],
                       weights=[55, 15, 10, 8, 3, 2, 1, 3, 2, 1])[0]


lines = ["# synthetic mixed-format sample, generated for testing"]
clock = start

for i in range(n):
    clock += timedelta(seconds=rng.randint(1, 20))
    fmt = rng.choices(["combined", "common", "json", "fixed8", "generic"],
                      weights=[40, 8, 25, 17, 10])[0]

    is_probe = rng.random() < 0.12
    if is_probe:
        ip = rng.choice(SCANNER_IPS)
        path = rng.choice(PROBE_PATHS)
        method = "GET"
    else:
        ip = rng.choice(V6_IPS) if rng.random() < 0.04 else rng.choice(NORMAL_IPS)
        path = rng.choice(DEAD_PATHS) if rng.random() < 0.06 else weighted_path()
        method = rng.choices(["GET", "POST", "HEAD", "PUT"],
                             weights=[80, 14, 4, 2])[0]

    status = pick_status(is_probe, path)
    ms = latency(path, status)
    size = 0 if status in (304, 204) else rng.randint(120, 24000)
    stamp_clf = clock.strftime("%d/%b/%Y:%H:%M:%S +0000")
    stamp_iso = clock.strftime("%Y-%m-%d %H:%M:%S")

    if fmt == "combined":
        lines.append(f'{ip} - - [{stamp_clf}] "{method} {path} HTTP/1.1" '
                     f'{status} {size} "-" "{rng.choice(AGENTS)}"')
    elif fmt == "common":
        lines.append(f'{ip} - - [{stamp_clf}] "{method} {path} HTTP/1.1" '
                     f'{status} {size}')
    elif fmt == "json":
        obj = {"timestamp": clock.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "level": "error" if status >= 500 else
                        ("warn" if status >= 400 else "info"),
               "client_ip": ip, "method": method, "path": path,
               "status": status, "duration_ms": ms, "bytes_sent": size}
        if rng.random() < 0.08:
            obj["path"] = path + ("&" if "?" in path else "?") + \
                "api_key=sk_live_9f3c2a77b1"
        if rng.random() < 0.05:
            obj["user"] = f"user{rng.randint(1,99)}@example.com"
        lines.append(json.dumps(obj))
    elif fmt == "fixed8":
        level = "ERROR" if status >= 500 else ("WARN" if status >= 400 else "INFO")
        lines.append(f'{stamp_iso} {level} {ip} {method} {path} {status} {ms}ms')
    else:
        level = "ERROR" if status >= 500 else ("WARN" if status >= 400 else "INFO")
        lines.append(f'{stamp_iso} {level} handled {method} {path} '
                     f'for {ip} status={status} in {ms}ms')

    # A little junk the parser should reject.
    if rng.random() < 0.03:
        lines.append(rng.choice([
            "  ",
            "Traceback (most recent call last):",
            '    File "app.py", line 42, in handler',
            "<<<<<<< merge conflict marker",
            "ip=203.0.113.99 no timestamp here at all",
        ]))

sys.stdout.write("\n".join(lines) + "\n")
