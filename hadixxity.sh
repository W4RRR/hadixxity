#!/usr/bin/env bash
#
# hadixxity.sh – End-to-end recon workflow inspired by Jason Haddix "Modern Recon"
#
# Phases covered:
#   0) Setup + directory structure + config loading
#   1) Corporate intelligence baseline (PitchBook, Crunchbase, brands)
#   2) WHOIS / RIR ownership checks
#   3) DNS (A/AAAA/MX/NS/TXT/CAA + reverse)
#   4) CT logs (crt.sh + companions)
#   5) ASN / BGP (bgp.he.net + WHOIS to netblocks)
#   6) Cloud ranges (AWS ip-ranges.json + mapping helper)
#   7) Shodan recon (cheat sheet + scripted searches)
#   8) SNI parsing helper (Dell-style shell pipeline)
#   9) SpiderFoot HX planning hook
#  10) Consolidation / asset lists
#
# Typical usage:
#   chmod +x hadixxity.sh
#   ./hadixxity.sh -d target.com -n "Target Corp" -o recon-target -S -C
#
# Optional env config:
#   cp config.env.example .hadixxity.env
#   edit keys, then run the script (env file is auto-loaded)
#
set -Eeuo pipefail

VERSION="2025-11-14"

# ---------- Colors ----------
C_RED="\033[31m"
C_GRN="\033[32m"
C_YEL="\033[33m"
C_BLU="\033[34m"
C_CYN="\033[36m"
C_RST="\033[0m"

info(){  echo -e "${C_CYN}[INFO]${C_RST} $*"; }
ok(){    echo -e "${C_GRN}[OK]  ${C_RST} $*"; }
warn(){  echo -e "${C_YEL}[WARN]${C_RST} $*"; }
err(){   echo -e "${C_RED}[ERR] ${C_RST} $*"; }
die(){   err "$*"; exit 1; }

trap 'rc=$?; err "Execution stopped at line $LINENO while running: $BASH_COMMAND (rc=$rc)"; exit $rc' ERR

ascii_banner(){
cat <<'EOF'
H   H   AAAAA  DDDD   III  XXXXX  XXXXX  III  TTTTT  Y   Y
H   H   A   A  D   D   I   X   X X   X   I     T     Y Y
HHHHH   AAAAA  D   D   I    X X   X X    I     T      Y
H   H   A   A  D   D   I   X   X X   X   I     T      Y
H   H   A   A  DDDD   III  XXXXX  XXXXX  III    T      Y
EOF
}

# ---------- Usage ----------
usage(){
  cat <<EOF
hadixxity.sh v${VERSION} – Modern Recon workflow

Usage:
  $0 -d DOMAIN [options]

Options:
  -d, --domain       Primary root domain (required)
  -n, --name         Company / program name (string)
  -i, --ip           Seed IP (e.g. 1.2.3.4)
  -a, --asn          Known ASNs (comma separated, e.g. "AS15169,AS16509")
  -o, --outdir       Output directory (default: recon-DOMAIN)
  -S, --shodan       Enable Shodan module (requires CLI + SHODAN_API_KEY)
  -C, --cloud        Enable AWS cloud helper (downloads ip-ranges.json)
  -X, --spiderfoot   Generate SpiderFoot HX automation plan
  -f, --config       Path to env file with API keys (default: ./.hadixxity.env)
  -h, --help         Show this help

Examples:
  $0 -d target.com
  $0 -d target.com -n "Target Corp" -S -C
  $0 -d target.com -i 52.179.197.205 -a "AS15169" -X

Legal:
  Run this script only against scopes where you have explicit authorization.
EOF
}

# ---------- Globals ----------
TARGET_DOMAIN=""
COMPANY_NAME=""
SEED_IP=""
ASNS=""
OUTDIR=""
CONFIG_FILE=""
USE_SHODAN=0
USE_CLOUD=0
USE_SPIDERFOOT=0

# Directories (filled later)
META_DIR=""
INTEL_DIR=""
WHOIS_DIR=""
DNS_DIR=""
ASN_DIR=""
CT_DIR=""
CLOUD_DIR=""
SHODAN_DIR=""
SNI_DIR=""
NOTES_DIR=""
SPIDERFOOT_DIR=""
REPORTS_DIR=""

# ---------- Helpers ----------
need_cmd(){
  command -v "$1" >/dev/null 2>&1 || die "Command '$1' not found in \$PATH. Please install it first."
}

load_config_file(){
  local chosen="$1"
  local fallback="${HADIXXITY_CONFIG:-.hadixxity.env}"
  local cfg=""

  if [[ -n "${chosen}" ]]; then
    cfg="$chosen"
  elif [[ -f "$fallback" ]]; then
    cfg="$fallback"
  elif [[ -f "./hadixxity.env" ]]; then
    cfg="./hadixxity.env"
  fi

  [[ -z "$cfg" ]] && return 0

  info "Loading config file: ${cfg}"
  # shellcheck disable=SC1090
  set -a
  source "$cfg"
  set +a
}

ensure_shodan_ready(){
  [[ "$USE_SHODAN" -eq 1 ]] || return 0
  if ! command -v shodan >/dev/null 2>&1; then
    warn "Shodan CLI not found. Disabling Shodan module."
    USE_SHODAN=0
    return 0
  fi
  if [[ -z "${SHODAN_API_KEY:-}" ]]; then
    warn "SHODAN_API_KEY is not defined; CLI queries may fail."
  fi
}

create_structure(){
  info "Preparing directory tree under: ${OUTDIR}"
  mkdir -p "${OUTDIR}"/{meta,intel,whois,dns,asn,ct,cloud,shodan,sni,notes,spiderfoot,reports}

  META_DIR="${OUTDIR}/meta"
  INTEL_DIR="${OUTDIR}/intel"
  WHOIS_DIR="${OUTDIR}/whois"
  DNS_DIR="${OUTDIR}/dns"
  ASN_DIR="${OUTDIR}/asn"
  CT_DIR="${OUTDIR}/ct"
  CLOUD_DIR="${OUTDIR}/cloud"
  SHODAN_DIR="${OUTDIR}/shodan"
  SNI_DIR="${OUTDIR}/sni"
  NOTES_DIR="${OUTDIR}/notes"
  SPIDERFOOT_DIR="${OUTDIR}/spiderfoot"
  REPORTS_DIR="${OUTDIR}/reports"

  {
    echo "TARGET_DOMAIN=${TARGET_DOMAIN}"
    echo "COMPANY_NAME=${COMPANY_NAME}"
    echo "SEED_IP=${SEED_IP}"
    echo "ASNS=${ASNS}"
    echo "USE_SHODAN=${USE_SHODAN}"
    echo "USE_CLOUD=${USE_CLOUD}"
    echo "USE_SPIDERFOOT=${USE_SPIDERFOOT}"
    echo "TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  } > "${META_DIR}/target-info.txt"

  ok "Directory layout ready."
}

# ---------- Phase 1: Corporate intelligence ----------
capture_corporate_intel(){
  local file="${INTEL_DIR}/${TARGET_DOMAIN}.corporate-intel.md"
  info "[PHASE 1] Building corporate intelligence checklist"
  cat <<EOF > "${file}"
# Phase 1 – Corporate / brand intelligence

- Primary entity: ${COMPANY_NAME:-Unknown}
- Anchor domains: ${TARGET_DOMAIN}
- Known seed IP/host: ${SEED_IP:-N/A}

## Tasks (manual OSINT)
- Query PitchBook / Crunchbase for acquisitions, subsidiaries, brand names.
- Record ticker symbols, DBAs, international branches, holding companies.
- Track marketing domains, SaaS portals, partner portals mentioned in filings.
- Add each discovered name to the \`${NOTES_DIR}/brand-names.txt\` file for downstream WHOIS / CT / DNS passes.

## Output expectation
- List of company/brand strings.
- Optional CSV with acquisition close dates.
- Candidate domains to expand recon scope.
EOF
  ok "[PHASE 1] Corporate intel template saved at ${file}"
}

# ---------- Phase 2: WHOIS / RIR ----------
recon_whois(){
  info "[PHASE 2] WHOIS lookups for ${TARGET_DOMAIN}"
  whois "${TARGET_DOMAIN}" > "${WHOIS_DIR}/${TARGET_DOMAIN}.whois.txt" 2>&1 || warn "Domain WHOIS failed"
  ok "WHOIS saved to whois/${TARGET_DOMAIN}.whois.txt"

  local ips
  ips=$(dig +short "${TARGET_DOMAIN}" A "${TARGET_DOMAIN}" AAAA | sort -u || true)
  if [[ -n "${ips}" ]]; then
    info "[PHASE 2] Running WHOIS on resolved IPs"
    echo "${ips}" | tee "${WHOIS_DIR}/${TARGET_DOMAIN}.ips.txt"
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      whois "${ip}" > "${WHOIS_DIR}/${ip}.whois.txt" 2>&1 || warn "WHOIS on IP ${ip} failed"
    done <<< "${ips}"
    ok "IP WHOIS bundle stored."
  else
    warn "No A/AAAA answers for ${TARGET_DOMAIN}."
  fi

  if [[ -n "${SEED_IP}" ]]; then
    info "[PHASE 2] WHOIS on seed IP ${SEED_IP}"
    whois "${SEED_IP}" > "${WHOIS_DIR}/${SEED_IP}.seed.whois.txt" 2>&1 || warn "WHOIS on seed IP failed"
  fi
}

# ---------- Phase 3: DNS ----------
recon_dns(){
  local domain="$1"
  info "[PHASE 3] DNS sweep for ${domain}"

  dig +noall +answer "${domain}" A    > "${DNS_DIR}/${domain}.A.txt"    2>/dev/null || true
  dig +noall +answer "${domain}" AAAA > "${DNS_DIR}/${domain}.AAAA.txt" 2>/dev/null || true
  dig +noall +answer "${domain}" MX   > "${DNS_DIR}/${domain}.MX.txt"   2>/dev/null || true
  dig +noall +answer "${domain}" NS   > "${DNS_DIR}/${domain}.NS.txt"   2>/dev/null || true
  dig +noall +answer "${domain}" TXT  > "${DNS_DIR}/${domain}.TXT.txt"  2>/dev/null || true
  dig +noall +answer "${domain}" CAA  > "${DNS_DIR}/${domain}.CAA.txt"  2>/dev/null || true
  dig +noall +answer "${domain}" SOA  > "${DNS_DIR}/${domain}.SOA.txt"  2>/dev/null || true

  local ips
  ips=$(dig +short "${domain}" A "${domain}" AAAA | sort -u || true)
  if [[ -n "${ips}" ]]; then
    info "[PHASE 3] Reverse DNS on resolved IPs"
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      host "${ip}" || true
    done <<< "${ips}" > "${DNS_DIR}/${domain}.reverse.txt" 2>&1
  fi

  local mail_file="${DNS_DIR}/${domain}.mail-security.txt"
  {
    echo "# SPF"
    dig +short "${domain}" TXT | grep -i "spf" || true
    echo
    echo "# DMARC"
    dig +short "_dmarc.${domain}" TXT || true
    echo
    echo "# DKIM (selector s1)"
    dig +short "s1._domainkey.${domain}" TXT || true
  } > "${mail_file}"
  ok "[PHASE 3] DNS outputs stored under dns/"
}

# ---------- Phase 4: CT logs ----------
recon_ct(){
  info "[PHASE 4] Querying crt.sh for ${TARGET_DOMAIN}"
  local json="${CT_DIR}/${TARGET_DOMAIN}.crtsh.raw.json"
  local subs="${CT_DIR}/${TARGET_DOMAIN}.subdomains.txt"

  if command -v jq >/dev/null 2>&1; then
    local url="https://crt.sh/?q=%25${TARGET_DOMAIN}&output=json"
    curl -s "${url}" > "${json}" || warn "curl crt.sh JSON failed"
    jq -r '.[].name_value' "${json}" 2>/dev/null \
      | tr ' ' '\n' \
      | sed 's/\*\.//g' \
      | grep -F ".${TARGET_DOMAIN#*.}" \
      | sort -u > "${subs}" || true
    ok "[PHASE 4] Candidate subdomains saved to ${subs}"
  else
    warn "jq missing; skipping structured crt.sh parsing."
  fi

  cat <<EOF > "${CT_DIR}/${TARGET_DOMAIN}.ct-tools.txt"
Manual CT sources to pivot:
- https://crt.sh/?q=%25${TARGET_DOMAIN}
- https://search.censys.io/certificates?q=${TARGET_DOMAIN}
- https://riddler.io/search?q=${TARGET_DOMAIN}
- https://dnsdumpster.com/
EOF
}

# ---------- Phase 5: ASN / BGP ----------
recon_asn(){
  info "[PHASE 5] ASN and BGP scoping"
  {
    echo "# Hurricane Electric BGP Toolkit"
    echo "https://bgp.he.net/search?search%5Bsearch%5D=${TARGET_DOMAIN}&commit=Search"
    if [[ -n "${SEED_IP}" ]]; then
      echo
      echo "Seed IP (${SEED_IP})"
      echo "https://bgp.he.net/ip/${SEED_IP}"
    fi
    if [[ -n "${ASNS}" ]]; then
      echo
      echo "Manual ASNs:"
      IFS=',' read -r -a arr <<< "${ASNS}"
      for asn in "${arr[@]}"; do
        asn_trimmed=$(echo "$asn" | tr -d ' ')
        [[ -z "$asn_trimmed" ]] && continue
        echo "  ${asn_trimmed} -> https://bgp.he.net/${asn_trimmed}"
      done
    fi
  } > "${ASN_DIR}/${TARGET_DOMAIN}.bgp-he-links.txt"

  local ips
  ips=$(dig +short "${TARGET_DOMAIN}" A "${TARGET_DOMAIN}" AAAA | sort -u || true)
  if [[ -n "$ips" ]]; then
    {
      echo "# WHOIS highlights for ${TARGET_DOMAIN} resolved IPs"
      while read -r ip; do
        [[ -z "$ip" ]] && continue
        echo
        echo "## ${ip}"
        whois "${ip}" 2>/dev/null | egrep -i 'NetRange|CIDR|OriginAS|origin|Organization|org-name' || true
      done <<< "${ips}"
    } > "${ASN_DIR}/${TARGET_DOMAIN}.ip-whois-summary.txt"
    ok "[PHASE 5] ASN helper files written under asn/"
  else
    warn "[PHASE 5] No IPs resolved for ASN enrichment."
  fi
}

# ---------- Phase 6: AWS cloud ----------
recon_cloud_aws(){
  [[ "$USE_CLOUD" -eq 1 ]] || { warn "[PHASE 6] AWS cloud module disabled (-C to enable)."; return 0; }
  if ! command -v jq >/dev/null 2>&1; then
    warn "[PHASE 6] jq not found; cannot parse AWS ip-ranges.json."
    return 0
  fi

  info "[PHASE 6] Downloading AWS ip-ranges.json"
  local json="${CLOUD_DIR}/aws-ip-ranges.json"
  curl -s "https://ip-ranges.amazonaws.com/ip-ranges.json" -o "${json}" || { warn "Failed to fetch AWS ranges"; return 0; }
  jq -r '.prefixes[] | [.region, .service, .ip_prefix] | @tsv' "${json}" > "${CLOUD_DIR}/aws-ipv4-prefixes.tsv" || true

  local ips
  ips=$(dig +short "${TARGET_DOMAIN}" A | sort -u || true)
  if [[ -n "$ips" ]]; then
    {
      echo -e "ip\tmatching_prefix\tregion\tservice"
      while read -r ip; do
        [[ -z "$ip" ]] && continue
        echo -e "${ip}\t[use ipcalc against aws-ipv4-prefixes.tsv]\t?\t?"
      done <<< "${ips}"
    } > "${CLOUD_DIR}/${TARGET_DOMAIN}.aws-ip-mapping.tsv"
  fi
  ok "[PHASE 6] Cloud helper outputs stored in cloud/."
}

# ---------- Phase 7: Shodan ----------
generate_shodan_playbook(){
  local cheat="${SHODAN_DIR}/${TARGET_DOMAIN}.cheatsheet.txt"
  cat <<'EOF' > "${cheat}"
# Shodan search ideas (adapted from Modern Recon cheat sheet)
## IPs & subnets
ip:52.179.197.205
hostname:"example.com"
net:"52.179.197.0/24"
port:21
"ftp"
"ftp" port:21
ASN:"AS8075"

## Geography
country:"US"
city:"New York"
region:"NY"
postal:"92127"
geo:"40.759487,-73.978356,2"

## Systems / products
os:"Windows Server 2008"
os:"Linux 2.6.x"
org:"Microsoft"
product:"Cisco C3550 Router"
product:"nginx" version:"1.8.1"
category:"ics"
category:"malware"
port:"445" "shares"

## Web / SSL
title:"Index of /ftp"
html:"XML-RPC server accepts"
http.component:"php"
ssl.version:"sslv3"
ssl.cert.expired:true
port:80 has_screenshot:true
port:3389 has_screenshot:true

## Other
after:"01/01/23"
before:"12/31/22"
vuln:"CVE-2017-0143"
tag:"database"
EOF
}

recon_shodan(){
  [[ "$USE_SHODAN" -eq 1 ]] || { warn "[PHASE 7] Shodan module disabled (-S to enable)."; return 0; }
  info "[PHASE 7] Running base Shodan pivots"

  local q_org=""
  [[ -n "${COMPANY_NAME}" ]] && q_org="org:\"${COMPANY_NAME}\""

  local q1="ssl.cert.subject:\"${TARGET_DOMAIN}\""
  local q2="hostname:\"${TARGET_DOMAIN}\""
  local q_http="(ssl.cert.subject:\"${TARGET_DOMAIN}\" OR hostname:\"${TARGET_DOMAIN}\") port:80,443,8080,8443"
  local q_rdp="(ssl.cert.subject:\"${TARGET_DOMAIN}\" OR hostname:\"${TARGET_DOMAIN}\") port:3389"

  shodan search --fields ip_str,port,org,hostnames "${q1}" \
    > "${SHODAN_DIR}/${TARGET_DOMAIN}.ssl-subject.txt" 2>&1 || warn "Shodan query ssl-subject failed"
  shodan search --fields ip_str,port,org,hostnames "${q2}" \
    > "${SHODAN_DIR}/${TARGET_DOMAIN}.hostname.txt" 2>&1 || warn "Shodan query hostname failed"
  if [[ -n "${q_org}" ]]; then
    shodan search --fields ip_str,port,org,hostnames "${q_org}" \
      > "${SHODAN_DIR}/${TARGET_DOMAIN}.org.txt" 2>&1 || warn "Shodan query org failed"
  fi
  shodan search --fields ip_str,port,org,hostnames,title "${q_http}" \
    > "${SHODAN_DIR}/${TARGET_DOMAIN}.http-stack.txt" 2>&1 || warn "Shodan HTTP query failed"
  shodan search --fields ip_str,port,org,hostnames,os "${q_rdp}" \
    > "${SHODAN_DIR}/${TARGET_DOMAIN}.rdp.txt" 2>&1 || warn "Shodan RDP query failed"

  generate_shodan_playbook
  ok "[PHASE 7] Shodan outputs ready in shodan/."
}

# ---------- Phase 8: SNI parsing helper ----------
process_sni_outputs(){
  local sni_pattern="${1:-${TARGET_DOMAIN}}"
  info "[PHASE 8] Parsing SNI text dumps in ${SNI_DIR}"

  local out="${SNI_DIR}/${sni_pattern}.sni-hosts.txt"
  if ! compgen -G "${SNI_DIR}/*.txt" >/dev/null 2>&1; then
    warn "[PHASE 8] No *.txt SNI dumps found in ${SNI_DIR}. Copy your scanner output first."
    return 0
  fi

  (
    cd "${SNI_DIR}"
    cat *.txt \
      | grep -F ".${sni_pattern}" \
      | awk -F'--' '{print $2}' \
      | tr ' ' '\n' \
      | tr '[' ' ' \
      | sed 's/ //' \
      | sed 's/\]/ /' \
      | grep -F ".${sni_pattern}" \
      | sed 's/^\*\.//' \
      | sort -u
  ) > "${out}"

  ok "[PHASE 8] Parsed hostnames saved to ${out}"
}

# ---------- Phase 9: SpiderFoot HX ----------
plan_spiderfoot_osint(){
  [[ "$USE_SPIDERFOOT" -eq 1 ]] || return 0

  local file="${SPIDERFOOT_DIR}/${TARGET_DOMAIN}.spiderfoot-plan.md"
  info "[PHASE 9] Writing SpiderFoot HX plan"
  cat <<EOF > "${file}"
# SpiderFoot HX playbook

- Console URL: ${SPIDERFOOT_URL:-https://spiderfoot.example.com}
- API key (if applicable): ${SPIDERFOOT_API_KEY:-<set-in-config>}
- Suggested modules: DNS, WHOIS, CT logs, Shodan, Censys, leaks, geography, paste sites.

## Suggested scan seeds
- Domain: ${TARGET_DOMAIN}
- Company name: ${COMPANY_NAME:-N/A}
- Seed IP: ${SEED_IP:-N/A}
- ASNs: ${ASNS:-N/A}

## Workflow
1. Create a new scan titled "${TARGET_DOMAIN}-modern-recon".
2. Enable enrichment modules listed above plus any custom connectors available to your subscription tier.
3. Export results as JSON/CSV and place them in \`${SPIDERFOOT_DIR}/exports/\`.
4. Re-run this script's consolidation phase to merge SpiderFoot findings into asset lists.
EOF
  ok "[PHASE 9] SpiderFoot HX instructions stored at ${file}"
}

# ---------- Phase 10: Consolidation ----------
consolidate_assets(){
  info "[PHASE 10] Consolidating assets"
  mkdir -p "${REPORTS_DIR}"

  local domains_file="${REPORTS_DIR}/domains.txt"
  local subdomains_file="${REPORTS_DIR}/subdomains.txt"
  local ips_file="${REPORTS_DIR}/ips.txt"

  printf "%s\n" "${TARGET_DOMAIN}" > "${domains_file}"
  [[ -n "${COMPANY_NAME}" ]] && printf "%s\n" "${COMPANY_NAME}" > "${REPORTS_DIR}/company.txt"

  : > "${subdomains_file}"
  [[ -f "${CT_DIR}/${TARGET_DOMAIN}.subdomains.txt" ]] && cat "${CT_DIR}/${TARGET_DOMAIN}.subdomains.txt" >> "${subdomains_file}"
  [[ -f "${SNI_DIR}/${TARGET_DOMAIN}.sni-hosts.txt" ]] && cat "${SNI_DIR}/${TARGET_DOMAIN}.sni-hosts.txt" >> "${subdomains_file}"
  sort -u "${subdomains_file}" -o "${subdomains_file}" || true

  : > "${ips_file}"
  if [[ -f "${WHOIS_DIR}/${TARGET_DOMAIN}.ips.txt" ]]; then
    cat "${WHOIS_DIR}/${TARGET_DOMAIN}.ips.txt" >> "${ips_file}"
  fi
  if [[ -f "${DNS_DIR}/${TARGET_DOMAIN}.A.txt" ]]; then
    awk '$4=="A"{print $5}' "${DNS_DIR}/${TARGET_DOMAIN}.A.txt" >> "${ips_file}" || true
  fi
  sort -u "${ips_file}" -o "${ips_file}" || true

  {
    echo "# Recon consolidation"
    echo "- Domains: ${domains_file}"
    echo "- Subdomains: ${subdomains_file}"
    echo "- IPs: ${ips_file}"
    echo "- ASN helper: ${ASN_DIR}/${TARGET_DOMAIN}.ip-whois-summary.txt"
    echo "- Cloud helper: ${CLOUD_DIR}/${TARGET_DOMAIN}.aws-ip-mapping.tsv"
    echo "- Shodan queries: ${SHODAN_DIR}/${TARGET_DOMAIN}.cheatsheet.txt"
    echo "- SpiderFoot plan: ${SPIDERFOOT_DIR}/${TARGET_DOMAIN}.spiderfoot-plan.md"
  } > "${REPORTS_DIR}/README.txt"

  ok "[PHASE 10] Asset lists generated under reports/."
}

# ---------- Summary ----------
print_summary(){
  echo
  echo -e "${C_BLU}===================== SUMMARY =====================${C_RST}"
  echo "Target:        ${TARGET_DOMAIN}"
  [[ -n "${COMPANY_NAME}" ]] && echo "Company:       ${COMPANY_NAME}"
  [[ -n "${SEED_IP}" ]] && echo "Seed IP:       ${SEED_IP}"
  [[ -n "${ASNS}" ]] && echo "Manual ASNs:   ${ASNS}"
  echo "Output path:   ${OUTDIR}"
  echo
  echo "Key folders:"
  echo "  ${INTEL_DIR}      -> Corporate intel notes"
  echo "  ${WHOIS_DIR}      -> WHOIS snapshots"
  echo "  ${DNS_DIR}        -> DNS answers + mail security"
  echo "  ${CT_DIR}         -> crt.sh outputs"
  echo "  ${ASN_DIR}        -> BGP / netblock helpers"
  echo "  ${CLOUD_DIR}      -> AWS range data"
  echo "  ${SHODAN_DIR}     -> CLI exports + cheat sheet"
  echo "  ${SNI_DIR}        -> Raw + parsed SNI dumps"
  echo "  ${SPIDERFOOT_DIR} -> HX plan"
  echo "  ${REPORTS_DIR}    -> Consolidated lists"
  echo
  echo "Next steps:"
  echo "  - Merge DNS + CT + SNI + SpiderFoot subdomains."
  echo "  - Resolve subdomains to IPs and cross with ASNs/cloud prefixes."
  echo "  - Feed prioritized targets into nmap/httpx/ffuf or your active stack."
  echo
}

# ---------- Arg parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)
      TARGET_DOMAIN="$2"; shift 2;;
    -n|--name)
      COMPANY_NAME="$2"; shift 2;;
    -i|--ip)
      SEED_IP="$2"; shift 2;;
    -a|--asn)
      ASNS="$2"; shift 2;;
    -o|--outdir)
      OUTDIR="$2"; shift 2;;
    -S|--shodan)
      USE_SHODAN=1; shift 1;;
    -C|--cloud)
      USE_CLOUD=1; shift 1;;
    -X|--spiderfoot)
      USE_SPIDERFOOT=1; shift 1;;
    -f|--config)
      CONFIG_FILE="$2"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      err "Unknown option: $1"
      usage
      exit 1;;
  esac
done

[[ -z "$TARGET_DOMAIN" ]] && { usage; die "You must specify -d / --domain"; }
[[ -z "${OUTDIR:-}" ]] && OUTDIR="recon-${TARGET_DOMAIN}"

# ---------- Runtime ----------
load_config_file "${CONFIG_FILE}"

need_cmd dig
need_cmd whois
need_cmd curl
need_cmd host

if ! command -v jq >/dev/null 2>&1; then
  warn "jq not found. AWS parsing and CT JSON extraction will be limited."
fi

ensure_shodan_ready
create_structure
ascii_banner
info "Launching hadixxity.sh – Modern Recon for ${TARGET_DOMAIN}"

capture_corporate_intel
recon_whois
recon_dns "${TARGET_DOMAIN}"
recon_ct
recon_asn
recon_cloud_aws
recon_shodan
plan_spiderfoot_osint

warn "[PHASE 8] Reminder: drop your TLS/SNI scanner outputs into ${SNI_DIR}"
warn "             then run: process_sni_outputs \"${TARGET_DOMAIN}\""

consolidate_assets
print_summary
ok "hadixxity.sh completed."

exit 0

