"""Indicator extraction: the entities that link evidence across files.

Rules: regex plus validation, no guessing. Every entity is returned with its kind and the exact
normalised value (IPs as written, domains/emails lower-cased, hashes lower-cased).
"""
from __future__ import annotations

import ipaddress
import re

KINDS = ("ip", "domain", "url", "email", "hash", "path", "user", "host")

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_URL = re.compile(r"\bhttps?://[^\s\"'<>()\]]+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
_HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_WINPATH = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|]+|\\Device\\[^\s\"'<>|]+")
_UNIXPATH = re.compile(r"(?<![\w/])/(?:etc|var|usr|home|tmp|opt|bin|root|srv)/[^\s\"'<>|]*")
_PSEUDO_USER = re.compile(r"\bUSER-\d{2,6}\b")
_PSEUDO_HOST = re.compile(r"\bHOST-\d{2,6}\b", re.I)
_KV_USER = re.compile(r"\b(?:user(?:name)?|duser|suser|account)\s*[=:]\s*\"?([A-Za-z0-9._\\-]{2,64})", re.I)

# Words that look like domains but are file names or code in log text.
_NOT_TLD = {"java", "jar", "py", "js", "exe", "dll", "log", "txt", "zip", "json", "xml", "html", "htm", "php",
            "csv", "sys", "png", "jpg", "jpeg", "gif", "pdf", "doc", "docx", "xls", "xlsx", "tmp", "bak", "ini",
            "cfg", "conf", "sh", "bat", "ps1", "msi", "class", "go", "rb", "ts", "md", "yml", "yaml", "lock"}
_SKIP_USERS = {"-", "none", "null", "n/a", "na", "unknown", "system"}


def _valid_ip(s: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_multicast or str(ip).startswith("255."))


def extract(text: str | None, fields: dict | None = None) -> list[tuple[str, str]]:
    """Return sorted unique (kind, value) pairs found in `text` and in structured `fields`."""
    found: set[tuple[str, str]] = set()
    t = text or ""
    for f in ("src_ip", "dst_ip"):
        v = (fields or {}).get(f)
        if isinstance(v, str) and _valid_ip(v.strip()):
            found.add(("ip", v.strip()))
    if t:
        urls = _URL.findall(t)
        for u in urls:
            found.add(("url", u.rstrip(".,;")))
        emails = _EMAIL.findall(t)
        for e in emails:
            found.add(("email", e.lower()))
        for ip in _IPV4.findall(t):
            if _valid_ip(ip):
                found.add(("ip", ip))
        email_domains = {e.split("@", 1)[1].lower() for e in emails}
        for d in _DOMAIN.findall(t):
            d_l = d.lower()
            tld = d_l.rsplit(".", 1)[-1]
            if tld in _NOT_TLD or d_l in email_domains or _IPV4.fullmatch(d_l):
                continue
            found.add(("domain", d_l))
        for h in _HASH.findall(t):
            found.add(("hash", h.lower()))
        for p in _WINPATH.findall(t) + _UNIXPATH.findall(t):
            found.add(("path", p.rstrip(".,;)")))
        for u in _PSEUDO_USER.findall(t):
            found.add(("user", u))
        for m in _KV_USER.finditer(t):
            u = m.group(1)
            if u.lower() not in _SKIP_USERS:
                found.add(("user", u))
        for h in _PSEUDO_HOST.findall(t):
            found.add(("host", h.upper()))
    # A URL's host is also a domain (links a browser visit to DNS/proxy logs).
    for kind, v in list(found):
        if kind == "url":
            host = re.sub(r"^https?://", "", v, flags=re.I).split("/")[0].split(":")[0].lower()
            if _valid_ip(host):
                found.add(("ip", host))
            elif "." in host:
                found.add(("domain", host))
    return sorted(found)
