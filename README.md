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

- **Name** → derives likely username variants (`johnsmith`, `john.smith`,
  `john_smith`, `jsmith`, `smithjohn`) and sweeps them against WhatsMyName.
  Prompts you to pick which variants to check and whether to run a quick
  ~30-site subset or the full 600-site sweep.
- **Username** → presence checks against **600+ platforms** using the
  community-maintained [WhatsMyName](https://github.com/WebBreacher/WhatsMyName)
  database, plus a deep-dive on the GitHub API
- **Email** → Gravatar profile lookup (linked accounts, bio, location), MX
  records and mail provider detection
- **Domain** → A / AAAA / MX / NS / TXT records via Cloudflare DoH
- **IP** → geolocation, ISP, ASN, reverse DNS
- **Phone** → country, carrier, region, line type, timezone (offline, via
  Google's `libphonenumber`)

The WhatsMyName JSON is cached at `~/.cache/bosif/wmn-data.json` and refreshed
weekly. Username checks run in parallel so the slow part finishes quickly.

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
> 13

  Full name (e.g. John Smith): Linus Torvalds
  Email address: linus@kernel.org

collected:
  • name        Linus Torvalds
  • email       linus@kernel.org

derived:
  • derived domain 'kernel.org' from email
  • resolved domain to IP '139.178.84.217'

── Name — Linus Torvalds ──────────────────────────────
  derived these usernames from Linus Torvalds:

    1  linustorvalds
    2  linus.torvalds
    3  linus_torvalds
    4  ltorvalds
    5  torvaldslinus

  check which? [a]ll quick / [numbers] / [t]horough all / [s]kip
  > 1

  running quick sweep on 1 variant(s)

── Variant 'linustorvalds' (from Linus Torvalds) ──────
  [coding]
  ✓ GitHub                 https://github.com/linustorvalds
  ✓ GitLab                 https://gitlab.com/linustorvalds
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

## Credits

Username enumeration is powered by
[WhatsMyName](https://github.com/WebBreacher/WhatsMyName) by `@WebBreacher`
and contributors, licensed CC BY-SA 4.0. bosif fetches and caches their
`wmn-data.json` to do its checks. Massive thanks to that project — please
contribute new site detections [upstream](https://github.com/WebBreacher/WhatsMyName)
rather than to bosif.

## License

MIT — see [LICENSE](LICENSE).