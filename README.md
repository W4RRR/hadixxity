## Hadixxity – Modern Recon Workflow

Hadixxity condenses Jason Haddix's *Modern Recon* techniques into a single automation-friendly workflow that keeps both manual OSINT context (PitchBook, SpiderFoot HX) and CLI-heavy tasks (WHOIS, DNS, CT, Shodan) stitched together.

```
 _   _    _    ____ ___ ____  _   _  ____ ___ _____ ___
| | | |  / \  / ___|_ _|  _ \| \ | |/ ___|_ _| ____|_ _|
| |_| | / _ \| |    | || |_) |  \| | |  _ | ||  _|  | |
|  _  |/ ___ \ |___ | ||  _ <| |\  | |_| || || |___ | |
|_| |_/_/   \_\____|___|_| \_\_| \_|\____|___|_____|___|
```

### Features
- Opinionated 10-phase flow: corporate intel → WHOIS/DNS/CT → ASN/BGP → cloud → Shodan → SNI parsing → SpiderFoot HX → consolidation.
- Multi-domain aware runs (repeat `-d`) with automatic IP harvesting and BGP/ARIN pivots (BGPView API + bgp.he.net links).
- Hurricane Electric “Network Tools” style summaries (DMARC/SPF/DKIM/BIMI, reverse IP, HTTP headers) saved per domain.
- Automatic apex harvesting (CT, SNI, MX) feeding an optional subfinder → httpx loop; you can still hand a custom list via `-A`.
- Aggregated Shodan helpers: cheat sheet, per-domain CLI exports + auto-generated `asn:` / `net:` queries from discovered data.
- Tuning knobs for operational security: custom or random User-Agent, fixed/random delays between requests.
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
- `PROJECTDISCOVERY_API_KEY` – unlocks all sources in the `subfinder`/`httpx` pipelines (auto-apex + manual `-A`)

Copy `config.env.example` to `.hadixxity.env`, populate the values you need, and the script will auto-source it on launch.

### Quick Start
```bash
cp config.env.example .hadixxity.env          # put your API keys here
dos2unix .hadixxity.env                       # ensure LF line endings on Unix hosts
chmod +x hadixxity.sh
./hadixxity.sh -d target.com -d target.org -n "Target Corp" -S -C -X
```
O bien, usa el script auxiliar para preparar todo tras clonar el repositorio:
```bash
./install.sh
# edita .hadixxity.env con tus claves y ejecuta hadixxity.sh
```

### User-Agent & delay controls
- `-U "MyReconBot/1.0"` define un User-Agent personalizado para todas las peticiones HTTP internas (curl, crt.sh, bgpview, etc.).
- `--random-ua` elige aleatoriamente un User-Agent realista (Chrome, Firefox, Safari, curl…) al arrancar.
- `--delay 0.5` añade un sleep fijo (soporta decimales) antes de cada petición de red/CLI intensiva.
- `--random-delay 0.2:1.2` alterna aleatoriamente entre los valores indicados para simular actividad humana y evitar rate limits.

Puedes combinar `--random-ua` con cualquiera de los modos de delay; si defines ambos (`--delay` y `--random-delay`) prevalece el último.

Key flags:
- `-S` enables Shodan module (requires CLI + key)
- `-C` downloads & parses AWS IP ranges
- `-X` drops a SpiderFoot HX action plan
- `-f` points to a custom env file with secrets
- `-A` feeds *your* file with apex domains into the subfinder → httpx loop described in the PDF (auto mode runs even sin este flag)

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
├─ reports/       # consolidated domains / subdomains / IPs / ASNs / prefixes / apex-auto
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
- Even sin `-A`, Hadixxity construye `meta/apex-auto.txt` con apex descubiertos vía CT/SNI/MX (ignorando proveedores comunes) y ejecuta la pipeline automáticamente.
- Resultados (manual o auto) aterrizan en `notes/apex-httpx/<apex>.httpx.txt` con los mismos switches del slide (status code, title, content length, ASN, geolocalización, multi-puerto, random UA, etc.).
- El fichero `reports/apex-auto.txt` conserva la lista usada para que puedas revisarla / depurarla.
- Para desbloquear todos los proveedores de ProjectDiscovery (Sources/ASNmap, etc.) añade tu `PROJECTDISCOVERY_API_KEY` a `.hadixxity.env` o exporta `PDCP_API_KEY` antes de ejecutar.

### Shodan automation
- `shodan/<domain>.*.txt` contains the raw CLI exports (certificate CN, hostname search, org pivot, HTTP stack, RDP).
- `shodan/<domain>.cheatsheet.txt` keeps the Modern Recon dorks handy.
- `shodan/aggregated-queries.txt` auto-builds `asn:` and `net:` filters from everything the tool discovered (BGPView, DNS, manual seeds) so you can paste them straight into the CLI or web UI.

### SNI Parsing
- Drop any TLS/SNI hunter output (`*.txt`) into `sni/` and Hadixxity will auto-parse it for every apex during Phase 8.
- You can still run it manually if you want to re-process a subset:
  ```bash
  process_sni_outputs "target.com"
  ```
- Normalized hostnames land in `sni/<domain>.sni-hosts.txt` and get merged automatically into `reports/subdomains.txt`.

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

