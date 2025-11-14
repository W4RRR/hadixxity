## Hadixxity – Modern Recon Workflow

Hadixxity condenses Jason Haddix's *Modern Recon* techniques into a single automation-friendly workflow that keeps both manual OSINT context (PitchBook, SpiderFoot HX) and CLI-heavy tasks (WHOIS, DNS, CT, Shodan) stitched together.

```
H   H   AAAAA  DDDD   III  XXXXX  XXXXX  III  TTTTT  Y   Y
H   H   A   A  D   D   I   X   X X   X   I     T     Y Y
HHHHH   AAAAA  D   D   I    X X   X X    I     T      Y
H   H   A   A  D   D   I   X   X X   X   I     T      Y
H   H   A   A  DDDD   III  XXXXX  XXXXX  III    T      Y
```

### Features
- Opinionated 10-phase flow: corporate intel → WHOIS/DNS/CT → ASN/BGP → cloud → Shodan → SNI parsing → SpiderFoot HX → consolidation.
- Multi-domain aware runs (repeat `-d`) with automatic IP harvesting and BGP/ARIN pivots (BGPView API + bgp.he.net links).
- Hurricane Electric “Network Tools” style summaries (DMARC/SPF/DKIM/BIMI, reverse IP, HTTP headers) saved per domain.
- Optional apex pipeline (`-A apex.txt`) that replays the subfinder → httpx loop from the Modern Recon slides.
- Aggregated Shodan helpers: cheat sheet, per-domain CLI exports + auto-generated `asn:` / `net:` queries from discovered data.
- Config file loader (`.hadixxity.env`) for API keys (Shodan, SpiderFoot HX, SecurityTrails, Censys, ...).
- ASCII art banner so you remember you're in Hadixxity land.

### Requirements
- Bash (tested on GNU Bash 5+)
- Tools: `dig`, `host`, `whois`, `curl`
- Optional: `jq`, `shodan` CLI, `ipcalc`/`sipcalc`, `subfinder`, `httpx`

### API keys / config file
- `SHODAN_API_KEY` – CLI lookups when you pass `-S`
- `SPIDERFOOT_URL` / `SPIDERFOOT_API_KEY` – documents your HX console for `-X`
- `SECURITYTRAILS_API_KEY` – ready for DNS/history enrichment if you extend the script
- `CENSYS_API_ID` / `CENSYS_API_SECRET` – wired for future Censys modules

Copy `config.env.example` to `.hadixxity.env`, populate the values you need, and the script will auto-source it on launch.

### Quick Start
```bash
cp config.env.example .hadixxity.env          # put your API keys here
chmod +x hadixxity.sh
./hadixxity.sh -d target.com -d target.org -n "Target Corp" -S -C -X -A fisAPEXES
```

Key flags:
- `-S` enables Shodan module (requires CLI + key)
- `-C` downloads & parses AWS IP ranges
- `-X` drops a SpiderFoot HX action plan
- `-f` points to a custom env file with secrets
- `-A` feeds a file with apex domains into the subfinder → httpx loop described in the PDF

### Output Layout
```
recon-target.com/
├─ meta/          # target-info, domain list, resolved-ips/asns/prefixes
├─ intel/         # PitchBook / brand OSINT notes
├─ whois/         # domain + IP WHOIS
├─ dns/           # multi-record dig outputs + mail security + HE network tools snapshot
├─ ct/            # crt.sh JSON + helper links per domain
├─ asn/           # BGP HE links + BGPView JSON + summaries
├─ cloud/         # AWS ip-ranges + per-domain mapping helper
├─ shodan/        # CLI exports + cheat sheet + aggregated asn/net queries
├─ sni/           # drop TLS/SNI dumps here for parsing
├─ spiderfoot/    # HX plan + exports placeholder
├─ reports/       # consolidated domains / subdomains / IPs / ASNs / prefixes
└─ notes/         # free-form notes + `apex-httpx/` if you pass `-A`
```

### Automatic ASN / BGP mapping
- Every resolved A/AAAA host is appended to `meta/resolved-ips.txt`.
- BGPView API enrichment populates `asn/bgpview-ip-summary.txt`, `meta/resolved-asns.txt` and `meta/resolved-prefixes.txt`.
- Domain-oriented searches are saved under `asn/<domain>.bgpview-search.json` / `.txt`, together with markdown links back to `bgp.he.net`.
- Each IP summary includes the ARIN Whois-RWS URL so you can pivot straight into ownership/contact data if the block sits in ARIN space.

### Hurricane Electric “Network Tools” snapshot
- For each apex you get `dns/<domain>.network-tools.md`, bundling DMARC/SPF/DKIM/BIMI, MX/NS answers, reverse IP output and HTTP header captures.
- Raw headers live in `dns/<domain>.http-headers.txt`, emulating the HTTP Headers / OS detector widget from the HE toolbox.

### Apex recon loop (subfinder + httpx)
- Provide `-A fisAPEXES` (or any file with one apex per line) to replay the `subfinder -d ... | httpx ...` loop shown in the PDF.
- Results land in `notes/apex-httpx/<apex>.httpx.txt` with the exact switches from the slide (status code, title, content length, ASN, geolocation, multi-port probing, random UA, etc.).

### Shodan automation
- `shodan/<domain>.*.txt` contains the raw CLI exports (certificate CN, hostname search, org pivot, HTTP stack, RDP).
- `shodan/<domain>.cheatsheet.txt` keeps the Modern Recon dorks handy.
- `shodan/aggregated-queries.txt` auto-builds `asn:` and `net:` filters from everything the tool discovered (BGPView, DNS, manual seeds) so you can paste them straight into the CLI or web UI.

### SNI Parsing
After running your TLS/SNI hunter place its `.txt` outputs under `sni/` and invoke:
```bash
process_sni_outputs "target.com"
```
Parsed hostnames land in `sni/target.com.sni-hosts.txt` and automatically roll into the consolidated lists.

### SpiderFoot HX
- Put API / console data inside `.hadixxity.env`.
- Run with `-X` to generate `spiderfoot/<domain>.spiderfoot-plan.md`.
- Export HX results into `spiderfoot/exports/` and re-run Hadixxity to re-consolidate.

### Suggested Next Steps
- Feed `reports/subdomains.txt` to `httpx`, `ffuf`, etc.
- Cross `reports/ips.txt` with `cloud/aws-ipv4-prefixes.tsv` for cloud-region tagging.
- Paste the entries in `shodan/aggregated-queries.txt` straight into the CLI/Web UI to hunt across every ASN/prefix found.
- Extend `config.env.example` with more APIs (SecurityTrails, Censys) and wire new phases/functions as needed.

Happy hunting.

