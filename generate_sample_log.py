"""
Generuje realistyczny log dostepu nginx (format 'combined') z wplecionymi
anomaliami: brute-force logowania, skanowanie 404 i podejrzane user-agenty.
Deterministyczny (seed=42). Wynik: ../sample_logs/access.log
"""
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta

rng = np.random.default_rng(42)
OUT = Path(__file__).resolve().parent.parent / "sample_logs"
OUT.mkdir(exist_ok=True)

NORMAL_IPS = [f"192.168.1.{i}" for i in range(2, 60)] + \
             [f"83.{rng.integers(1,255)}.{rng.integers(1,255)}.{rng.integers(1,255)}" for _ in range(40)]
PATHS = ["/", "/products", "/products/123", "/cart", "/checkout", "/about",
         "/contact", "/blog", "/blog/post-1", "/search?q=shoes", "/api/products",
         "/static/app.css", "/static/app.js", "/favicon.ico", "/images/logo.png"]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 Safari/16.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4) AppleWebKit/605.1.15 Mobile Safari",
]
REFERERS = ["https://google.com/", "https://example.com/", "-", "https://example.com/products"]

def fmt(ip, dt, method, path, status, ua, ref="-", size=None):
    if size is None:
        size = int(rng.integers(200, 5000))
    ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0100")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'

lines = []
start = datetime(2024, 3, 10, 0, 0, 0)

# --- ruch normalny: 3 dni, wiekszy w godzinach 8-22 ---
for day in range(3):
    for _ in range(1200):
        hour = int(rng.choice(range(24), p=np.array(
            [1,1,1,1,1,2,3,5,7,8,8,8,7,7,8,8,8,7,6,5,4,3,2,1], dtype=float)
            / np.sum([1,1,1,1,1,2,3,5,7,8,8,8,7,7,8,8,8,7,6,5,4,3,2,1])))
        dt = start + timedelta(days=day, hours=hour,
                               minutes=int(rng.integers(0,60)), seconds=int(rng.integers(0,60)))
        ip = rng.choice(NORMAL_IPS)
        path = rng.choice(PATHS)
        # rozklad statusow: glownie 200, czasem 301/302, rzadko 404/500
        status = int(rng.choice([200,200,200,200,301,302,404,500],
                                p=[.74,.10,.05,.04,.03,.02,.015,.005]))
        lines.append((dt, fmt(ip, dt, rng.choice(["GET","GET","GET","POST"]),
                              path, status, rng.choice(UAS), rng.choice(REFERERS))))

# --- ANOMALIA 1: brute-force logowania (duzo 401 z jednego IP) ---
attacker1 = "203.0.113.66"
for _ in range(45):
    dt = start + timedelta(days=1, hours=2, minutes=int(rng.integers(0,40)), seconds=int(rng.integers(0,60)))
    lines.append((dt, fmt(attacker1, dt, "POST", "/login", 401,
                          "Mozilla/5.0 (X11; Linux x86_64) python-requests/2.31")))

# --- ANOMALIA 2: skanowanie sciezek (duzo 404) + narzedzie sqlmap/nikto ---
attacker2 = "198.51.100.23"
scan_paths = ["/admin", "/wp-login.php", "/.env", "/backup.zip", "/config.php",
              "/phpmyadmin", "/.git/config", "/api/v1/users", "/server-status",
              "/old", "/test.php", "/shell.php", "/admin/login", "/.aws/credentials"]
for _ in range(70):
    dt = start + timedelta(days=2, hours=4, minutes=int(rng.integers(0,50)), seconds=int(rng.integers(0,60)))
    ua = rng.choice(["sqlmap/1.7", "Nikto/2.5.0", "Mozilla/5.0 nmap-scan"])
    lines.append((dt, fmt(attacker2, dt, "GET", rng.choice(scan_paths), 404, ua)))

# --- ANOMALIA 3: kilka 403 z jeszcze innego IP ---
attacker3 = "203.0.113.99"
for _ in range(18):
    dt = start + timedelta(days=0, hours=23, minutes=int(rng.integers(0,40)))
    lines.append((dt, fmt(attacker3, dt, "GET", "/admin/config", 403,
                          "curl/8.2.1")))

# sortuj po czasie i zapisz
lines.sort(key=lambda x: x[0])
with open(OUT / "access.log", "w") as f:
    f.write("\n".join(l for _, l in lines) + "\n")

print(f"Zapisano {len(lines)} linii do {OUT/'access.log'}")
