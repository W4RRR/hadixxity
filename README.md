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
- Automatic directory scaffolding (`recon-<domain>` by default) with per-phase artifacts.
- Config file loader (`.hadixxity.env`) for API keys like Shodan or SpiderFoot.
- Shodan cheat sheet + base queries pre-baked.
- ASCII art banner so you remember you're in Hadixxity land.

### Requirements
- Bash (tested on GNU Bash 5+)
- Tools: `dig`, `host`, `whois`, `curl`
- Optional: `jq`, `shodan` CLI, `ipcalc`/`sipcalc` for manual steps

### Quick Start
```bash
cp config.env.example .hadixxity.env          # put your API keys here
chmod +x hadixxity.sh
./hadixxity.sh -d target.com -n "Target Corp" -S -C -X
```

Key flags:
- `-S` enables Shodan module (requires CLI + key)
- `-C` downloads & parses AWS IP ranges
- `-X` drops a SpiderFoot HX action plan
- `-f` points to a custom env file with secrets

### Output Layout
```
recon-target.com/
├─ meta/          # target-info, timestamps
├─ intel/         # PitchBook / brand OSINT notes
├─ whois/         # domain + IP WHOIS
├─ dns/           # multi-record dig outputs + mail security
├─ ct/            # crt.sh JSON + helper links
├─ asn/           # BGP HE links + netrange summaries
├─ cloud/         # AWS ip-ranges + mapping helper
├─ shodan/        # CLI exports + cheat sheet
├─ sni/           # drop TLS/SNI dumps here for parsing
├─ spiderfoot/    # HX plan + exports placeholder
├─ reports/       # consolidated domains / subdomains / IPs
└─ notes/         # free-form notes (brand names, etc.)
```

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
- Extend `config.env.example` with more APIs (SecurityTrails, Censys) and wire new phases/functions as needed.

Happy hunting.

