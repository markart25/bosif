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

__version__ = "0.1.0"

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

# Username platforms — (name, url-template, success-check)
# success-check: 'status' means 200 = exists, or a string that must be ABSENT from body
USERNAME_SITES = [
    ("GitHub",      "https://github.com/{u}",                     "status"),
    ("GitLab",      "https://gitlab.com/{u}",                     "status"),
    ("Reddit",      "https://www.reddit.com/user/{u}",            "status"),
    ("Twitter/X",   "https://twitter.com/{u}",                    "status"),
    ("Instagram",   "https://www.instagram.com/{u}/",             "status"),
    ("TikTok",      "https://www.tiktok.com/@{u}",                "status"),
    ("YouTube",     "https://www.youtube.com/@{u}",               "status"),
    ("Twitch",      "https://www.twitch.tv/{u}",                  "status"),
    ("Steam",       "https://steamcommunity.com/id/{u}",          "status"),
    ("Pinterest",   "https://www.pinterest.com/{u}/",             "status"),
    ("Medium",      "https://medium.com/@{u}",                    "status"),
    ("Dev.to",      "https://dev.to/{u}",                         "status"),
    ("HackerNews",  "https://news.ycombinator.com/user?id={u}",   "No such user."),
    ("Keybase",     "https://keybase.io/{u}",                     "status"),
    ("AUR",         "https://aur.archlinux.org/account/{u}",      "status"),
]


def check_username_site(name, url_tpl, mode, username):
    url = url_tpl.format(u=quote(username, safe=""))
    if mode == "status":
        s = http_head_status(url)
        found = s == 200
        return (name, url, found, s)
    else:
        s, body = http_get(url)
        if s == 200 and body and mode not in body:
            return (name, url, True, s)
        return (name, url, False, s)


def run_username_checks(username):
    section(f"Username — {username}")
    results = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(check_username_site, n, u, m, username): n
                for n, u, m in USERNAME_SITES}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                results.append((futs[f], "", False, str(e)))
    results.sort(key=lambda r: r[0].lower())
    found_count = 0
    for name, url, found, status in results:
        if found:
            ok(f"{name:<12}", url)
            found_count += 1
        else:
            miss(f"{name:<12}", f"HTTP {status}" if status else "no response")
    print(f"\n  {DIM}{found_count}/{len(results)} platforms returned a hit{RESET}")

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
    # Generate likely username variants
    first = parts[0].lower()
    last = parts[-1].lower() if len(parts) > 1 else ""
    variants = []
    if last:
        variants = [f"{first}{last}", f"{first}.{last}", f"{first}_{last}",
                    f"{first[0]}{last}", f"{last}{first}"]
    else:
        variants = [first]
    info("likely usernames to try", ", ".join(variants))
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
