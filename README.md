# bosif

> **B**asic **O**pen-**S**ource **I**ntelligence **F**ramework

A no-frills terminal OSINT tool. You tell it whatever info you have (a name, a
username, an email, a domain, an IP, a phone number — any combination), and it
fans out across public sources to fill in the blanks.

```
██████╗  ██████╗ ███████╗██╗███████╗
██╔══██╗██╔═══██╗██╔════╝██║██╔════╝
██████╔╝██║   ██║███████╗██║█████╗
██╔══██╗██║   ██║╚════██║██║██╔══╝
██████╔╝╚██████╔╝███████║██║██║
╚═════╝  ╚═════╝ ╚══════╝╚═╝╚═╝
```

## What it does

bosif takes the inputs you give it, derives anything it can (e.g. an email
gives it a username and a domain; a domain gives it an IP), then runs a set of
checks against public, no-auth sources:

- **Name** → suggests likely username variants
- **Username** → presence checks across 15 platforms (GitHub, GitLab, Reddit,
  Twitter/X, Instagram, TikTok, YouTube, Twitch, Steam, Pinterest, Medium,
  Dev.to, Hacker News, Keybase, AUR) plus a deep-dive on the GitHub API
- **Email** → Gravatar profile lookup (linked accounts, bio, location), MX
  records and mail provider detection
- **Domain** → A / AAAA / MX / NS / TXT records via Cloudflare DoH
- **IP** → geolocation, ISP, ASN, reverse DNS
- **Phone** → country, carrier, region, line type, timezone (offline, via
  Google's `libphonenumber`)

Username checks run in parallel so the slow part finishes quickly.

## Install

```sh
git clone https://github.com/markart25/bosif.git
cd bosif
pip install -r requirements.txt
python bosif.py
```

Or grab it from a release:

```sh
curl -L https://github.com/markart25/bosif/releases/latest/download/bosif.py -o bosif.py
pip install phonenumbers
python bosif.py
```

The only external dependency is `phonenumbers`, and it's only required if you
want phone lookups — everything else uses the Python standard library.

## Usage

Run it:

```sh
python bosif.py
```

It'll show a menu:

```
What info do you have?
Type the numbers of fields you can fill in (e.g. 125 or 2,3)

  1  Full name (e.g. John Smith)
  2  Username / handle
  3  Email address
  4  Domain (e.g. example.com)
  5  IP address
  6  Phone number (with country code, e.g. +447...)
```

Type the numbers of whatever you have — `1259` and `1,2,5,9` both work — and
it'll prompt you for each value, then run the checks.

### Example

```
> 23

  Username / handle: torvalds
  Email address: linus@kernel.org

collected:
  • username    torvalds
  • email       linus@kernel.org

derived:
  • • derived domain 'kernel.org' from email
  • • resolved domain to IP '139.178.84.217'

── Username — torvalds ────────────────────────────────
  ✓ AUR          https://aur.archlinux.org/account/torvalds
  ✓ GitHub       https://github.com/torvalds
  ✗ Instagram    (HTTP 404)
  ...

── GitHub profile — torvalds ──────────────────────────
  • name           Linus Torvalds
  • company        Linux Foundation
  • public_repos   7
  • followers      234567
  ...
```

## Notes & limits

- Several large sites (Instagram, TikTok, Twitter/X) aggressively block bots
  and may return false negatives or false positives. Treat presence checks as
  hints, not gospel.
- No API keys are required. If you want richer results, you could plug in HaveIBeenPwned, Shodan, or similar — patches welcome.
- bosif only queries public information that anyone could look up manually.
  Use it lawfully and responsibly.

## Roadmap

- Configurable output (JSON / CSV) for piping into other tools
- Plugin system for adding custom checks
- Optional HIBP / Shodan / VirusTotal integrations behind API keys
- Maybe an AUR package later

## License

MIT — see [LICENSE](LICENSE).
