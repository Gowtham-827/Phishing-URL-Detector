#!/usr/bin/env python3
"""Phishing URL Detector.

Scores URLs with transparent, rule-based heuristics (standard library only).
Each rule contributes points and an explanation, so every verdict is auditable.

Usage:
    python phishing_detector.py https://paypal-login.example.xyz/verify
    python phishing_detector.py --file urls.txt --json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from urllib.parse import unquote, urlparse

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
                   "click", "work", "support", "link", "rest", "icu", "country"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly"}
KEYWORDS = ("login", "signin", "verify", "update", "secure", "account", "banking",
            "confirm", "password", "wallet", "suspend", "invoice", "payment", "unlock")
BRANDS = {"paypal": "paypal.com", "google": "google.com", "microsoft": "microsoft.com",
          "apple": "apple.com", "amazon": "amazon.com", "facebook": "facebook.com",
          "netflix": "netflix.com", "instagram": "instagram.com",
          "linkedin": "linkedin.com", "github": "github.com"}
MULTI_PART_SUFFIXES = {"co.uk", "org.uk", "com.au", "co.in", "co.jp", "com.br"}


@dataclass
class Finding:
    rule: str
    points: int
    detail: str


@dataclass
class Result:
    url: str
    score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)


def registered_domain(host: str) -> str:
    """Return the registrable domain (heuristic, no public-suffix list needed)."""
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze(url: str) -> Result:
    raw = url.strip()
    normalized = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    findings: list[Finding] = []

    def add(rule: str, points: int, detail: str) -> None:
        findings.append(Finding(rule, points, detail))

    try:
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return Result(raw, 100, "High risk", [Finding("malformed_url", 100, "URL cannot be parsed")])
    if not host:
        return Result(raw, 100, "High risk", [Finding("no_host", 100, "URL has no hostname")])

    full = unquote(normalized).lower()
    reg = registered_domain(host)
    labels = host.split(".")
    tld = labels[-1]

    if parsed.scheme != "https":
        add("no_https", 10, "Connection is not encrypted (HTTP)")
    if is_ip(host):
        add("ip_host", 30, "Host is a raw IP address instead of a domain")
    if "@" in parsed.netloc:
        add("at_symbol", 25, "'@' in the authority can hide the real destination")
    if len(normalized) > 100:
        add("long_url", 10, f"URL is {len(normalized)} characters long")
    if len(labels) > 4 and not is_ip(host):
        add("many_subdomains", 15, f"{len(labels) - 2} subdomain levels")
    if host.count("-") >= 3:
        add("many_hyphens", 10, "Domain contains many hyphens")
    if "xn--" in host:
        add("punycode", 20, "Punycode domain may be an IDN homograph attack")
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", 15, f"TLD '.{tld}' is frequently abused")
    if host in SHORTENERS:
        add("url_shortener", 15, "URL shortener hides the final destination")
    hits = [k for k in KEYWORDS if k in full]
    if hits:
        add("keywords", min(5 * len(hits), 20), "Sensitive keywords: " + ", ".join(hits))
    for brand, official in BRANDS.items():
        if brand in host and reg != official:
            add("brand_impersonation", 30, f"Mentions '{brand}' but belongs to {reg}")
            break
    if shannon_entropy(labels[-2] if len(labels) >= 2 else host) > 3.6:
        add("high_entropy", 10, "Domain looks randomly generated")
    if parsed.port and parsed.port not in (80, 443):
        add("odd_port", 10, f"Non-standard port {parsed.port}")
    if full.count("//") > 1:
        add("double_slash", 5, "Embedded '//' in path may indicate redirection")
    if len(re.findall(r"%[0-9a-f]{2}", normalized.lower())) >= 5:
        add("heavy_encoding", 10, "Heavy percent-encoding obscures the URL")

    score = min(sum(f.points for f in findings), 100)
    verdict = "Low risk" if score < 25 else "Suspicious" if score < 50 else "High risk"
    return Result(raw, score, verdict, findings)


def load_urls(args: argparse.Namespace) -> list[str]:
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    return urls


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Heuristic phishing URL detector")
    p.add_argument("urls", nargs="*", help="URLs to analyze")
    p.add_argument("-f", "--file", help="text file with one URL per line")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args(argv)
    urls = load_urls(args)
    if not urls:
        try:
            entered = input("Enter a URL to check: ").strip()
        except EOFError:
            entered = ""
        if not entered:
            p.error("provide at least one URL or --file")
        urls = [entered]

    results = [analyze(u) for u in urls]
    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        for r in results:
            print(f"\n[{r.verdict.upper():<10}] score={r.score:>3}  {r.url}")
            for f in r.findings:
                print(f"    +{f.points:<3} {f.rule}: {f.detail}")
    return 1 if any(r.verdict == "High risk" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
