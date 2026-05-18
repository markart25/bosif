#!/usr/bin/env python3
"""
bosif - Basic Open-Source Intelligence Framework
A terminal-based OSINT tool that takes whatever info you have and tries to
fill in the rest.
"""

import sys
import re
import json
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote

__version__ = "0.2.0"

# ─── ANSI colours ──────────────────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

USER_AGENT = f"bosif/{__version__} (+https://github.com/markart25/bosif)"
TIMEOUT = 8

# WhatsMyName: community-maintained list of 600+ sites for username checks.
# Cached locally so we don't hit GitHub every run.
import os
import time
WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
WMN_CACHE = os.path.expanduser("~/.cache/bosif/wmn-data.json")
WMN_CACHE_MAX_AGE = 7 * 24 * 60 * 60  # 7 days

# ─── Banner ────────────────────────────────────────────────────────────────
BANNER = r"""
██████╗  ██████╗ ███████╗██╗███████╗
██╔══██╗██╔═══██╗██╔════╝██║██╔════╝
██████╔╝██║   ██║███████╗██║█████╗
██╔══██╗██║   ██║╚════██║██║██╔══╝
██████╔╝╚██████╔╝███████║██║██║
╚═════╝  ╚═════╝ ╚══════╝╚═╝╚═╝
"""


def banner():
    print(f"{YELLOW}{BANNER}{RESET}")
    print(f"  {DIM}Basic Open-Source Intelligence Framework  v{__version__}{RESET}\n")


# ─── HTTP helper ───────────────────────────────────────────────────────────
def http_get(url, timeout=TIMEOUT, headers=None):
    """Fetch a URL and return (status, body) or (None, error_string)."""
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    try:
        req = Request(url, headers=hdrs)
        with urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        return e.code, None
    except (URLError, socket.timeout) as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


def http_head_status(url, timeout=TIMEOUT):
    """Just check if a URL exists. Returns HTTP status or None."""
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT}, method="HEAD")
        with urlopen(req, timeout=timeout) as r:
            return r.status
    except HTTPError as e:
        return e.code
    except Exception:
        return None


# ─── Pretty output helpers ─────────────────────────────────────────────────
def section(title):
    print(f"\n{BOLD}{CYAN}── {title} {'─' * (60 - len(title))}{RESET}")


def ok(label, value=""):
    val = f" {value}" if value else ""
    print(f"  {GREEN}✓{RESET} {label}{val}")


def miss(label, reason=""):
    r = f" {DIM}({reason}){RESET}" if reason else ""
    print(f"  {RED}✗{RESET} {DIM}{label}{RESET}{r}")


def info(label, value=""):
    val = f" {value}" if value else ""
    print(f"  {BLUE}•{RESET} {label}{val}")


def warn(msg):
    print(f"  {YELLOW}!{RESET} {msg}")


# ─── Input prompts ─────────────────────────────────────────────────────────
FIELDS = [
    ("name", "Full name (e.g. John Smith)"),
    ("username", "Username / handle"),
    ("email", "Email address"),
    ("domain", "Domain (e.g. example.com)"),
    ("ip", "IP address"),
    ("phone", "Phone number (with country code, e.g. +447...)"),
]


def prompt_menu():
    """Show numbered field list and let user pick which they have."""
    print(f"{BOLD}What info do you have?{RESET}")
    print(f"{DIM}Type the numbers of fields you can fill in (e.g. 125 or 2,3){RESET}\n")
    for i, (_, desc) in enumerate(FIELDS, 1):
        print(f"  {YELLOW}{i}{RESET}  {desc}")
    print()
    raw = input(f"{BOLD}> {RESET}").strip()
    if not raw:
        return []
    digits = re.findall(r"\d", raw)
    picked = []
    for d in digits:
        idx = int(d) - 1
        if 0 <= idx < len(FIELDS) and FIELDS[idx][0] not in picked:
            picked.append(FIELDS[idx][0])
    return picked


def prompt_values(picked):
    """Ask user for the value of each picked field."""
    print()
    values = {}
    for key in picked:
        desc = dict(FIELDS)[key]
        v = input(f"  {CYAN}{desc}:{RESET} ").strip()
        if v:
            values[key] = v
    return values


# ─── Derivation: infer extra fields from what we have ──────────────────────
def derive(data):
    """Pull out additional fields we can infer from the inputs."""
    notes = []

    # email → username + domain
    if "email" in data:
        if "@" in data["email"]:
            local, _, dom = data["email"].partition("@")
            if "username" not in data:
                data["username"] = local
                notes.append(f"derived username '{local}' from email")
            if "domain" not in data:
                data["domain"] = dom
                notes.append(f"derived domain '{dom}' from email")

    # domain → IP
    if "domain" in data and "ip" not in data:
        try:
            ip = socket.gethostbyname(data["domain"])
            data["ip"] = ip
            notes.append(f"resolved domain to IP '{ip}'")
        except Exception:
            pass

    return notes


# ─── Checks ────────────────────────────────────────────────────────────────

# Curated high-signal sites for the "quick" mode when sweeping name variants.
# These are matched by name against the WMN list (case-insensitive substring).
QUICK_SITES = [
    "GitHub", "GitLab", "Reddit", "Twitter", "Instagram", "TikTok",
    "YouTube", "Twitch", "Steam", "Pinterest", "Medium", "Dev.to",
    "HackerNews", "Hacker News", "Keybase", "AUR", "Stack Overflow",
    "LinkedIn", "Facebook", "Spotify", "SoundCloud", "Last.fm",
    "DeviantArt", "Behance", "Dribbble", "Vimeo", "Telegram",
    "Discord", "Mastodon", "Bluesky",
]


def filter_to_quick(sites):
    """Return only WMN sites whose name matches our curated list."""
    out = []
    for s in sites:
        name = s.get("name", "").lower()
        for q in QUICK_SITES:
            if q.lower() in name:
                out.append(s)
                break
    return out
    """Load WhatsMyName site definitions, fetching/caching from GitHub.

    Cache lives at ~/.cache/bosif/wmn-data.json and refreshes every 7 days.
    """
    use_cache = False
    if os.path.exists(WMN_CACHE):
        age = time.time() - os.path.getmtime(WMN_CACHE)
        if age < WMN_CACHE_MAX_AGE:
            use_cache = True

    if not use_cache:
        print(f"  {DIM}fetching WhatsMyName site list...{RESET}")
        status, body = http_get(WMN_URL, timeout=15)
        if status == 200 and body:
            os.makedirs(os.path.dirname(WMN_CACHE), exist_ok=True)
            with open(WMN_CACHE, "w") as f:
                f.write(body)
        elif not os.path.exists(WMN_CACHE):
            warn(f"could not fetch WhatsMyName data: {body or f'HTTP {status}'}")
            warn("if you're on a network that intercepts HTTPS (e.g. school wifi),")
            warn("download the file manually and place it at:")
            warn(f"  {WMN_CACHE}")
            warn("from: " + WMN_URL)
            return None

    try:
        with open(WMN_CACHE) as f:
            return json.load(f)
    except Exception as e:
        warn(f"could not read WMN cache: {e}")
        return None


def check_wmn_site(site, username):
    """Run one WhatsMyName site check.

    A hit requires:
      - HTTP status matches site['e_code']  (expected/exists code)
      - site['e_string'] is in the body     (expected substring)
      - site['m_string'] is NOT in the body (missing substring absent)
    """
    name = site.get("name", "?")
    cat = site.get("cat", "")
    url = site["uri_check"].replace("{account}", quote(username, safe=""))
    pretty = site.get("uri_pretty", site["uri_check"]).replace(
        "{account}", quote(username, safe=""))

    # Strip disallowed characters if the site specifies them
    bad = site.get("strip_bad_char", "")
    if bad:
        clean_u = "".join(c for c in username if c not in bad)
        if clean_u != username:
            url = site["uri_check"].replace("{account}", quote(clean_u, safe=""))
            pretty = site.get("uri_pretty", site["uri_check"]).replace(
                "{account}", quote(clean_u, safe=""))

    headers = site.get("headers", {})
    status, body = http_get(url, headers=headers)

    e_code = site.get("e_code")
    e_string = site.get("e_string", "")
    m_string = site.get("m_string", "")

    found = False
    if status == e_code and body is not None:
        if e_string and e_string in body:
            if not m_string or m_string not in body:
                found = True

    return (name, cat, pretty, found, status)


def run_username_checks(username, max_workers=20, quick=False, label=None):
    header = label or f"Username — {username}"
    section(header)
    data = load_wmn_data()
    if not data:
        warn("falling back: no site list available")
        return

    sites = data.get("sites", [])
    if quick:
        sites = filter_to_quick(sites)

    print(f"  {DIM}checking {len(sites)} sites...{RESET}\n")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(check_wmn_site, s, username): s for s in sites}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                s = futs[f]
                results.append((s.get("name", "?"), s.get("cat", ""), "", False, str(e)))

    # Show only hits to keep output sane (15+ misses across 600 sites is noise).
    hits = [r for r in results if r[3]]
    hits.sort(key=lambda r: (r[1] or "", r[0].lower()))

    if hits:
        current_cat = None
        for name, cat, url, found, status in hits:
            if cat != current_cat:
                print(f"\n  {MAGENTA}[{cat or 'uncategorised'}]{RESET}")
                current_cat = cat
            ok(f"{name:<22}", url)
    else:
        miss("no hits across any platform")

    errs = sum(1 for r in results if not r[3] and not isinstance(r[4], int))
    print(f"\n  {DIM}{len(hits)} hits / {len(results)} sites checked"
          f"{f' ({errs} errored)' if errs else ''}{RESET}")

    # GitHub deep-dive
    gh_url = f"https://api.github.com/users/{quote(username)}"
    s, body = http_get(gh_url, headers={"Accept": "application/vnd.github+json"})
    if s == 200 and body:
        try:
            gh = json.loads(body)
            section(f"GitHub profile — {username}")
            for k in ("name", "company", "blog", "location", "email",
                      "bio", "public_repos", "followers", "created_at"):
                if gh.get(k):
                    info(f"{k:<14}", str(gh[k]))
        except Exception:
            pass


def check_gravatar(email):
    import hashlib
    section(f"Gravatar — {email}")
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{h}.json"
    s, body = http_get(url)
    if s == 200 and body:
        try:
            data = json.loads(body)
            entry = data.get("entry", [{}])[0]
            ok("Gravatar profile found", f"https://gravatar.com/{h}")
            for k in ("displayName", "preferredUsername", "currentLocation",
                      "aboutMe"):
                if entry.get(k):
                    info(f"{k:<18}", entry[k])
            for acc in entry.get("accounts", []):
                info("linked account", f"{acc.get('shortname','?')}: {acc.get('url','')}")
            return entry
        except Exception:
            miss("could not parse Gravatar response")
    else:
        miss("no Gravatar profile linked to this email")
    return None


def check_email_domain_mx(email):
    section(f"Email domain — {email.split('@')[-1]}")
    domain = email.split("@")[-1]
    # Try resolving MX via DNS-over-HTTPS (Cloudflare 1.1.1.1)
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX"
    s, body = http_get(url, headers={"Accept": "application/dns-json"})
    if s == 200 and body:
        try:
            data = json.loads(body)
            answers = data.get("Answer", [])
            if answers:
                for a in answers:
                    info("MX", a.get("data", ""))
                # Recognise common providers
                joined = " ".join(a.get("data", "").lower() for a in answers)
                providers = {
                    "google": "Google Workspace / Gmail",
                    "outlook": "Microsoft 365 / Outlook",
                    "protonmail": "ProtonMail",
                    "zoho": "Zoho Mail",
                    "icloud": "iCloud Mail",
                    "yahoodns": "Yahoo Mail",
                    "fastmail": "FastMail",
                }
                for needle, label in providers.items():
                    if needle in joined:
                        ok("provider detected", label)
                        break
            else:
                miss("no MX records found")
        except Exception:
            miss("could not parse DNS response")


def check_domain(domain):
    section(f"Domain — {domain}")
    # DNS records via DoH
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}"
        s, body = http_get(url, headers={"Accept": "application/dns-json"})
        if s == 200 and body:
            try:
                data = json.loads(body)
                for a in data.get("Answer", []):
                    info(f"{rtype:<5}", a.get("data", "")[:200])
            except Exception:
                pass


def check_ip(ip):
    section(f"IP — {ip}")
    try:
        ipobj = ipaddress.ip_address(ip)
        if ipobj.is_private:
            warn("this is a private IP — skipping public lookups")
            return
    except ValueError:
        miss("not a valid IP")
        return

    # ip-api.com free, no key needed
    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,query"
    s, body = http_get(url)
    if s == 200 and body:
        try:
            data = json.loads(body)
            if data.get("status") == "success":
                for k in ("country", "regionName", "city", "zip", "timezone",
                          "isp", "org", "as", "reverse"):
                    if data.get(k):
                        info(f"{k:<11}", str(data[k]))
                if data.get("lat") and data.get("lon"):
                    info("coords", f"{data['lat']}, {data['lon']}")
            else:
                miss("ip-api returned no data")
        except Exception:
            miss("could not parse ip-api response")

    # Reverse DNS
    try:
        rev = socket.gethostbyaddr(ip)
        info("PTR", rev[0])
    except Exception:
        pass


def check_phone(phone):
    section(f"Phone — {phone}")
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone as pn_tz
    except ImportError:
        warn("install the 'phonenumbers' package for phone lookups:")
        warn("  pip install phonenumbers")
        return
    try:
        num = phonenumbers.parse(phone, None)
    except Exception as e:
        miss(f"could not parse number: {e}")
        return
    valid = phonenumbers.is_valid_number(num)
    info("valid",       "yes" if valid else "no")
    info("country",     geocoder.description_for_number(num, "en") or "?")
    info("carrier",     carrier.name_for_number(num, "en") or "?")
    info("region",      phonenumbers.region_code_for_number(num) or "?")
    info("line type",   {
        0: "fixed line", 1: "mobile", 2: "fixed or mobile",
        3: "toll free", 4: "premium rate", 5: "shared cost",
        6: "VoIP", 7: "personal", 8: "pager", 9: "UAN",
        10: "unknown", 27: "voicemail"
    }.get(phonenumbers.number_type(num), "?"))
    tzs = pn_tz.time_zones_for_number(num)
    if tzs:
        info("timezones", ", ".join(tzs))
    info("E.164",       phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164))
    info("international", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL))


def check_name(name):
    section(f"Name — {name}")
    parts = name.strip().split()
    if len(parts) < 2:
        warn("name only has one part — try entering first and last name")
        return []

    first = parts[0].lower()
    last = parts[-1].lower()
    variants = [
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
        f"{last}{first}",
    ]
    # de-dupe while preserving order
    seen = set()
    variants = [v for v in variants if not (v in seen or seen.add(v))]

    print(f"  derived these usernames from {BOLD}{name}{RESET}:\n")
    for i, v in enumerate(variants, 1):
        print(f"    {YELLOW}{i}{RESET}  {v}")
    print()
    print(f"  check which? {DIM}[a]ll quick / [numbers] / [t]horough all / [s]kip{RESET}")
    print(f"  {DIM}default: 'a' — quick subset (~25 sites) across all variants{RESET}")
    raw = input(f"  {BOLD}> {RESET}").strip().lower()

    if raw == "s" or raw == "skip":
        info("skipping", "name-derived username sweep")
        return variants

    thorough = raw in ("t", "thorough")
    if raw and raw not in ("a", "all", "t", "thorough"):
        # parse numbers — pick specific variants
        digits = re.findall(r"\d", raw)
        chosen = []
        for d in digits:
            idx = int(d) - 1
            if 0 <= idx < len(variants) and variants[idx] not in chosen:
                chosen.append(variants[idx])
        if chosen:
            variants = chosen

    mode_label = "thorough" if thorough else "quick"
    print(f"\n  {DIM}running {mode_label} sweep on {len(variants)} variant(s){RESET}")

    for v in variants:
        run_username_checks(v, quick=not thorough,
                            label=f"Variant '{v}' (from {name})")
    return variants


# ─── Main flow ─────────────────────────────────────────────────────────────
def main():
    banner()
    picked = prompt_menu()
    if not picked:
        print(f"{RED}No fields selected. Exiting.{RESET}")
        return 1
    data = prompt_values(picked)
    if not data:
        print(f"{RED}No values entered. Exiting.{RESET}")
        return 1

    print(f"\n{BOLD}collected:{RESET}")
    for k, v in data.items():
        info(f"{k:<10}", v)

    notes = derive(data)
    if notes:
        print(f"\n{BOLD}derived:{RESET}")
        for n in notes:
            info("•", n)

    # Run checks in a sensible order
    if "name" in data:
        check_name(data["name"])
    if "username" in data:
        run_username_checks(data["username"])
    if "email" in data:
        check_gravatar(data["email"])
        check_email_domain_mx(data["email"])
    if "domain" in data:
        check_domain(data["domain"])
    if "ip" in data:
        check_ip(data["ip"])
    if "phone" in data:
        check_phone(data["phone"])

    print(f"\n{GREEN}{BOLD}done.{RESET}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}interrupted{RESET}")
        sys.exit(130)