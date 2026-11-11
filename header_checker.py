#!/usr/bin/env python3
"""
Web Security Header Checker
---------------------------
Grades the HTTP security posture of a URL: security headers, cookie flags,
CORS, and information leakage. Produces a score, a letter grade, and fixes.

ONLY scan sites you own or have written permission to test.

Usage:
    pip install requests
    python header_checker.py https://example.com
    python header_checker.py https://example.com --json report.json
    python header_checker.py https://example.com --html report.html
"""

import argparse
import json
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests

# ---------- Rule definitions ----------
# Each header: (name, points, why it matters, recommended value)
HEADER_RULES = [
    ("Content-Security-Policy", 25,
     "Mitigates XSS and data injection by restricting content sources.",
     "default-src 'self'; object-src 'none'; frame-ancestors 'none'"),
    ("Strict-Transport-Security", 20,
     "Forces HTTPS and prevents SSL-stripping downgrade attacks.",
     "max-age=31536000; includeSubDomains"),
    ("X-Content-Type-Options", 10,
     "Stops browsers MIME-sniffing responses into executable types.",
     "nosniff"),
    ("X-Frame-Options", 10,
     "Prevents clickjacking by blocking framing (or use CSP frame-ancestors).",
     "DENY"),
    ("Referrer-Policy", 10,
     "Limits URL leakage to other sites via the Referer header.",
     "strict-origin-when-cross-origin"),
    ("Permissions-Policy", 5,
     "Restricts powerful browser features (camera, mic, geolocation).",
     "geolocation=(), camera=(), microphone=()"),
    ("Cross-Origin-Opener-Policy", 5,
     "Isolates your browsing context from cross-origin windows.",
     "same-origin"),
    ("Cross-Origin-Resource-Policy", 5,
     "Controls which origins may load your resources.",
     "same-origin"),
]

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


class Finding:
    def __init__(self, category, name, status, points, max_points, detail, fix=""):
        self.category = category
        self.name = name
        self.status = status  # PASS / WARN / FAIL
        self.points = points
        self.max_points = max_points
        self.detail = detail
        self.fix = fix

    def to_dict(self):
        return self.__dict__


# ---------- Checks ----------
def check_headers(headers):
    findings = []
    for name, pts, why, rec in HEADER_RULES:
        value = headers.get(name)
        if value is None:
            findings.append(Finding("Headers", name, "FAIL", 0, pts,
                                    f"Missing. {why}", f"Add: {name}: {rec}"))
            continue

        # Extra quality checks for the important headers
        if name == "Content-Security-Policy":
            weak = []
            if "'unsafe-inline'" in value:
                weak.append("'unsafe-inline'")
            if "'unsafe-eval'" in value:
                weak.append("'unsafe-eval'")
            if " * " in f" {value} " or "default-src *" in value:
                weak.append("wildcard source")
            if weak:
                findings.append(Finding("Headers", name, "WARN", pts // 2, pts,
                                        f"Present but weak: {', '.join(weak)}.",
                                        "Remove unsafe directives; use nonces or hashes."))
                continue

        if name == "Strict-Transport-Security":
            try:
                age = int(value.lower().split("max-age=")[1].split(";")[0])
            except (IndexError, ValueError):
                age = 0
            if age < 15552000:  # 180 days
                findings.append(Finding("Headers", name, "WARN", pts // 2, pts,
                                        f"max-age too short ({age}s).",
                                        f"Use: {rec}"))
                continue

        if name == "X-Frame-Options" and value.upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(Finding("Headers", name, "WARN", pts // 2, pts,
                                    f"Unusual value: {value}", f"Use: {rec}"))
            continue

        findings.append(Finding("Headers", name, "PASS", pts, pts, f"Set: {value[:80]}"))
    return findings


def check_info_leak(headers):
    findings = []
    leaked = [(h, headers[h]) for h in LEAKY_HEADERS if h in headers]
    if leaked:
        detail = "; ".join(f"{h}: {v}" for h, v in leaked)
        findings.append(Finding("Info Leak", "Server fingerprinting", "WARN", 0, 5,
                                f"Reveals technology details: {detail}",
                                "Remove or genericize these headers."))
    else:
        findings.append(Finding("Info Leak", "Server fingerprinting", "PASS", 5, 5,
                                "No obvious version disclosure headers."))
    return findings


def check_cookies(response):
    findings = []
    raw_cookies = []
    # urllib3 exposes multiple Set-Cookie headers via getlist
    try:
        raw_cookies = response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        sc = response.headers.get("Set-Cookie")
        if sc:
            raw_cookies = [sc]

    if not raw_cookies:
        findings.append(Finding("Cookies", "Cookie flags", "PASS", 5, 5,
                                "No cookies set on this response (nothing to misconfigure)."))
        return findings

    for c in raw_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        problems = []
        if "secure" not in low:
            problems.append("missing Secure")
        if "httponly" not in low:
            problems.append("missing HttpOnly")
        if "samesite" not in low:
            problems.append("missing SameSite")
        elif "samesite=none" in low and "secure" not in low:
            problems.append("SameSite=None without Secure")

        if problems:
            findings.append(Finding("Cookies", f"Cookie '{name}'", "FAIL", 0, 5,
                                    ", ".join(problems) + ".",
                                    "Set: Secure; HttpOnly; SameSite=Lax (or Strict)."))
        else:
            findings.append(Finding("Cookies", f"Cookie '{name}'", "PASS", 5, 5,
                                    "Secure, HttpOnly, and SameSite all set."))
    return findings


def check_cors(url, session, timeout):
    """Send a request with a foreign Origin and see if it is reflected."""
    findings = []
    evil = "https://evil.example"
    try:
        r = session.get(url, headers={"Origin": evil}, timeout=timeout)
    except requests.RequestException:
        return findings
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == evil and acac == "true":
        findings.append(Finding("CORS", "CORS policy", "FAIL", 0, 10,
                                "Reflects arbitrary Origin WITH credentials allowed.",
                                "Use a strict allowlist of trusted origins."))
    elif acao == "*" and acac == "true":
        findings.append(Finding("CORS", "CORS policy", "FAIL", 0, 10,
                                "Wildcard origin with credentials (invalid and risky).",
                                "Use a strict origin allowlist."))
    elif acao == evil or acao == "*":
        findings.append(Finding("CORS", "CORS policy", "WARN", 5, 10,
                                f"Allows broad origin access ({acao}).",
                                "Restrict to known origins unless this is a public API."))
    else:
        findings.append(Finding("CORS", "CORS policy", "PASS", 10, 10,
                                "No permissive CORS behavior detected."))
    return findings


def check_transport(url, session, timeout):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(Finding("Transport", "HTTPS", "FAIL", 0, 10,
                                "Site is served over plain HTTP.",
                                "Enable TLS and redirect all HTTP to HTTPS."))
        return findings

    findings.append(Finding("Transport", "HTTPS", "PASS", 5, 10, "Served over HTTPS."))
    # Does plain HTTP redirect to HTTPS?
    http_url = url.replace("https://", "http://", 1)
    try:
        r = session.get(http_url, timeout=timeout, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
            findings.append(Finding("Transport", "HTTP to HTTPS redirect", "PASS", 5, 10,
                                    f"Redirects with {r.status_code}."))
        else:
            findings.append(Finding("Transport", "HTTP to HTTPS redirect", "WARN", 0, 10,
                                    "HTTP does not redirect to HTTPS.",
                                    "Add a permanent redirect from HTTP to HTTPS."))
    except requests.RequestException:
        findings.append(Finding("Transport", "HTTP to HTTPS redirect", "PASS", 5, 10,
                                "Port 80 not reachable (acceptable)."))
    return findings


# ---------- Scoring and output ----------
def grade(pct):
    for threshold, letter in [(95, "A+"), (85, "A"), (75, "B"), (60, "C"), (45, "D")]:
        if pct >= threshold:
            return letter
    return "F"


COLORS = {"PASS": "\033[92m", "WARN": "\033[93m", "FAIL": "\033[91m", "END": "\033[0m"}


def print_report(url, findings, score, max_score, letter):
    use_color = sys.stdout.isatty()
    c = (lambda k: COLORS[k]) if use_color else (lambda k: "")
    print(f"\nSecurity Header Report for {url}")
    print(f"Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    current = None
    for f in findings:
        if f.category != current:
            current = f.category
            print(f"\n[{current}]")
        print(f"  {c(f.status)}{f.status:<4}{c('END')} {f.name} ({f.points}/{f.max_points})")
        print(f"       {f.detail}")
        if f.fix and f.status != "PASS":
            print(f"       Fix: {f.fix}")
    pct = round(score / max_score * 100)
    print("\n" + "=" * 70)
    print(f"SCORE: {score}/{max_score} ({pct}%)   GRADE: {letter}\n")


def write_html(path, url, findings, score, max_score, letter):
    colors = {"PASS": "#2e7d32", "WARN": "#f9a825", "FAIL": "#c62828"}
    rows = "".join(
        f"<tr><td>{f.category}</td><td>{f.name}</td>"
        f"<td style='color:{colors[f.status]};font-weight:bold'>{f.status}</td>"
        f"<td>{f.points}/{f.max_points}</td><td>{f.detail}</td><td>{f.fix}</td></tr>"
        for f in findings
    )
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Security Report</title>
<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:8px;text-align:left}}th{{background:#222;color:#fff}}
.grade{{font-size:3rem;font-weight:bold}}</style></head><body>
<h1>Security Report: {url}</h1>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<p class="grade">Grade {letter} ({score}/{max_score})</p>
<table><tr><th>Category</th><th>Check</th><th>Status</th><th>Points</th><th>Detail</th><th>Fix</th></tr>
{rows}</table></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


def main():
    p = argparse.ArgumentParser(description="Web security header checker")
    p.add_argument("url", help="Target URL (only scan sites you are authorized to test)")
    p.add_argument("--json", help="Write JSON report to this path")
    p.add_argument("--html", help="Write HTML report to this path")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--yes", action="store_true",
                   help="Confirm you are authorized to test this target")
    args = p.parse_args()

    url = args.url if args.url.startswith("http") else "https://" + args.url

    if not args.yes:
        ans = input(f"Do you own or have written permission to test {url}? [y/N] ")
        if ans.strip().lower() != "y":
            print("Aborted. Only scan targets you are authorized to test.")
            sys.exit(1)

    session = requests.Session()
    session.headers["User-Agent"] = "HeaderChecker/1.0 (educational security scan)"

    try:
        resp = session.get(url, timeout=args.timeout, allow_redirects=True)
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        sys.exit(2)

    findings = []
    findings += check_transport(url, session, args.timeout)
    findings += check_headers(resp.headers)
    findings += check_cookies(resp)
    findings += check_cors(url, session, args.timeout)
    findings += check_info_leak(resp.headers)

    score = sum(f.points for f in findings)
    max_score = sum(f.max_points for f in findings)
    letter = grade(score / max_score * 100)

    print_report(resp.url, findings, score, max_score, letter)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"url": resp.url, "score": score, "max": max_score,
                       "grade": letter, "findings": [f.to_dict() for f in findings]},
                      fh, indent=2)
        print(f"JSON saved to {args.json}")
    if args.html:
        write_html(args.html, resp.url, findings, score, max_score, letter)
        print(f"HTML saved to {args.html}")


if __name__ == "__main__":
    main()
