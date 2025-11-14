#!/usr/bin/env bash
#
# hadixxity.sh – End-to-end recon workflow inspired by Jason Haddix "Modern Recon"
#
# Phases covered:
#   0) Setup + directory structure + config loading
#   1) Corporate intelligence baseline (PitchBook, Crunchbase, brands)
#   2) WHOIS / RIR ownership checks (w/ ARIN Whois-RWS links)
#   3) DNS + mail posture (DMARC/DKIM/SPF/BIMI + reverse IP + HTTP headers)
#   4) CT logs (crt.sh + companions)
#   5) ASN / BGP (auto IP discovery → bgp.he.net pivot + BGPView enrichment)
#   6) Cloud ranges (AWS ip-ranges.json + mapping helper)
#   7) Shodan recon (cheat sheet + scripted queries by ASN/prefix)
#   8) Passive recon extras (subfinder/httpx loop + SNI parsing helper)
#   9) SpiderFoot HX planning hook
#  10) Consolidation / asset lists ready for active recon
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
  -d, --domain       Primary root domain (required, can be specified multiple times)
  -n, --name         Company / program name (string)
  -i, --ip           Optional seed IP (e.g. 1.2.3.4) – auto discovery runs regardless
  -a, --asn          Optional seed ASNs (comma separated, e.g. "AS15169,AS16509")
  -o, --outdir       Output directory (default: recon-DOMAIN)
  -S, --shodan       Enable Shodan module (requires CLI + SHODAN_API_KEY)
  -C, --cloud        Enable AWS cloud helper (downloads ip-ranges.json)
  -X, --spiderfoot   Generate SpiderFoot HX automation plan
  -A, --apex-file    File with apex domains for subfinder→httpx pipeline
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
declare -a TARGET_DOMAINS=()
TARGET_DOMAIN=""
COMPANY_NAME=""
SEED_IP=""
ASNS=""
OUTDIR=""
CONFIG_FILE=""
USE_SHODAN=0
USE_CLOUD=0
USE_SPIDERFOOT=0
APEX_LIST_FILE=""

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
ALL_DOMAINS_FILE=""
ALL_IPS_FILE=""
ALL_ASNS_FILE=""
ALL_PREFIXES_FILE=""
AWS_RANGES_READY=0
AWS_RANGES_JSON=""

# ---------- Helpers ----------
need_cmd(){
  command -v "$1" >/dev/null 2>&1 || die "Command '$1' not found in \$PATH. Please install it first."
}

ensure_file(){
  local file="$1"
  [[ -f "$file" ]] || : > "$file"
}

record_unique_line(){
  local file="$1"
  local line="$2"
  [[ -z "${line// }" ]] && return 0
  ensure_file "$file"
  grep -Fxq "$line" "$file" 2>/dev/null || echo "$line" >> "$file"
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
  AWS_RANGES_JSON="${CLOUD_DIR}/aws-ip-ranges.json"

  ALL_DOMAINS_FILE="${META_DIR}/domains.txt"
  ALL_IPS_FILE="${META_DIR}/resolved-ips.txt"
  ALL_ASNS_FILE="${META_DIR}/resolved-asns.txt"
  ALL_PREFIXES_FILE="${META_DIR}/resolved-prefixes.txt"
  : > "${ALL_DOMAINS_FILE}"
  : > "${ALL_IPS_FILE}"
  : > "${ALL_ASNS_FILE}"
  : > "${ALL_PREFIXES_FILE}"
  for domain in "${TARGET_DOMAINS[@]}"; do
    record_unique_line "${ALL_DOMAINS_FILE}" "${domain}"
  done

  {
    echo "TARGET_DOMAIN=${TARGET_DOMAIN}"
    if ((${#TARGET_DOMAINS[@]} > 1)); then
      printf "TARGET_DOMAINS=%s\n" "$(printf "%s," "${TARGET_DOMAINS[@]}" | sed 's/,$//')"
    fi
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
  {
    cat <<'EOF'
# Phase 1 – Corporate / brand intelligence

## Primary entity
EOF
    echo "- ${COMPANY_NAME:-Unknown}"
    echo
    echo "## Anchor domains"
    for domain in "${TARGET_DOMAINS[@]}"; do
      echo "- ${domain}"
    done
    echo
    cat <<EOF
## Seeds provided manually
- IP: ${SEED_IP:-N/A}
- ASN(s): ${ASNS:-N/A}

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
  } > "${file}"
  ok "[PHASE 1] Corporate intel template saved at ${file}"
}

# ---------- Phase 2: WHOIS / RIR ----------
recon_whois(){
  local domain="$1"
  info "[PHASE 2] WHOIS lookups for ${domain}"
  whois "${domain}" > "${WHOIS_DIR}/${domain}.whois.txt" 2>&1 || warn "Domain WHOIS failed for ${domain}"
  ok "WHOIS saved to whois/${domain}.whois.txt"

  local ips
  ips=$(dig +short "${domain}" A "${domain}" AAAA | sort -u || true)
  if [[ -n "${ips}" ]]; then
    info "[PHASE 2] Running WHOIS on resolved IPs for ${domain}"
    echo "${ips}" | tee "${WHOIS_DIR}/${domain}.ips.txt"
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      record_unique_line "${ALL_IPS_FILE}" "${ip}"
      whois "${ip}" > "${WHOIS_DIR}/${ip}.whois.txt" 2>&1 || warn "WHOIS on IP ${ip} failed"
    done <<< "${ips}"
    ok "IP WHOIS bundle stored for ${domain}."
  else
    warn "No A/AAAA answers for ${domain}."
  fi

  if [[ -n "${SEED_IP}" ]]; then
    info "[PHASE 2] WHOIS on seed IP ${SEED_IP}"
    record_unique_line "${ALL_IPS_FILE}" "${SEED_IP}"
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
      record_unique_line "${ALL_IPS_FILE}" "${ip}"
      host "${ip}" || true
    done <<< "${ips}" > "${DNS_DIR}/${domain}.reverse.txt" 2>&1
  fi

  local mail_file="${DNS_DIR}/${domain}.mail-security.txt"
  local spf_txt dmarc_txt dkim_txt bimi_txt
  spf_txt=$(dig +short "${domain}" TXT 2>/dev/null | grep -i "spf" | tr -d '"' | paste -sd ';' - || true)
  dmarc_txt=$(dig +short "_dmarc.${domain}" TXT 2>/dev/null | tr -d '"' | paste -sd ';' - || true)
  dkim_txt=$(dig +short "s1._domainkey.${domain}" TXT 2>/dev/null | tr -d '"' | paste -sd ';' - || true)
  bimi_txt=$(dig +short "default._bimi.${domain}" TXT 2>/dev/null | tr -d '"' | paste -sd ';' - || true)
  {
    echo "# SPF"
    echo "${spf_txt:-No SPF record detected.}"
    echo
    echo "# DMARC"
    echo "${dmarc_txt:-No DMARC record detected.}"
    echo
    echo "# DKIM (selector s1)"
    echo "${dkim_txt:-No DKIM selector s1 record detected.}"
    echo
    echo "# BIMI (default selector)"
    echo "${bimi_txt:-No BIMI record detected.}"
  } > "${mail_file}"

  capture_http_headers "${domain}"
  emit_network_tools_snapshot "${domain}" "${spf_txt}" "${dmarc_txt}" "${dkim_txt}" "${bimi_txt}"
  ok "[PHASE 3] DNS outputs stored under dns/"
}

capture_http_headers(){
  local domain="$1"
  local out="${DNS_DIR}/${domain}.http-headers.txt"
  {
    echo "# HTTPS (443)"
    curl -skI --max-time 15 "https://${domain}" || echo "[curl] HTTPS probe failed for ${domain}"
    echo
    echo "# HTTP (80)"
    curl -sI --max-time 15 "http://${domain}" || echo "[curl] HTTP probe failed for ${domain}"
  } > "${out}"
}

emit_network_tools_snapshot(){
  local domain="$1"
  local spf="$2"
  local dmarc="$3"
  local dkim="$4"
  local bimi="$5"
  local file="${DNS_DIR}/${domain}.network-tools.md"
  local http_file="${DNS_DIR}/${domain}.http-headers.txt"
  local reverse_file="${DNS_DIR}/${domain}.reverse.txt"
  {
    echo "# Hurricane Electric style network tools snapshot – ${domain}"
    echo
    echo "## MX Lookup"
    if [[ -s "${DNS_DIR}/${domain}.MX.txt" ]]; then
      cat "${DNS_DIR}/${domain}.MX.txt"
    else
      echo "No MX answers recorded."
    fi
    echo
    echo "## NS Lookup"
    if [[ -s "${DNS_DIR}/${domain}.NS.txt" ]]; then
      cat "${DNS_DIR}/${domain}.NS.txt"
    else
      echo "No NS answers recorded."
    fi
    echo
    echo "## DMARC Lookup"
    echo "${dmarc:-No DMARC record detected.}"
    echo
    echo "## SPF Record Checker"
    echo "${spf:-No SPF record detected.}"
    echo
    echo "## DKIM Lookup (selector s1)"
    echo "${dkim:-No DKIM selector record detected.}"
    echo
    echo "## BIMI Checker"
    echo "${bimi:-No BIMI record detected.}"
    echo
    echo "## Reverse IP Lookup"
    if [[ -s "${reverse_file}" ]]; then
      cat "${reverse_file}"
    else
      echo "No reverse DNS data captured yet."
    fi
    echo
    echo "## HTTP Headers / Website OS hints"
    if [[ -s "${http_file}" ]]; then
      echo '```'
      cat "${http_file}"
      echo '```'
    else
      echo "HTTP header probe not available."
    fi
    echo
    echo "## Manual follow-ups"
    echo "- Email Blacklist Check: https://networktools.he.net/checkblacklist/"
    echo "- IP Location Lookup: https://networktools.he.net/iplocation/"
    echo "- HTTP Headers / OS detector: https://networktools.he.net/httpheaders/"
    echo "- Ping / traceroute / additional lookups: https://networktools.he.net/"
  } > "${file}"
}

# ---------- Phase 4: CT logs ----------
recon_ct(){
  local domain="$1"
  info "[PHASE 4] Querying crt.sh for ${domain}"
  local json="${CT_DIR}/${domain}.crtsh.raw.json"
  local subs="${CT_DIR}/${domain}.subdomains.txt"

  if command -v jq >/dev/null 2>&1; then
    local url="https://crt.sh/?q=%25${domain}&output=json"
    curl -s "${url}" > "${json}" || warn "curl crt.sh JSON failed"
    jq -r '.[].name_value' "${json}" 2>/dev/null \
      | tr ' ' '\n' \
      | sed 's/\*\.//g' \
      | grep -F ".${domain#*.}" \
      | sort -u > "${subs}" || true
    ok "[PHASE 4] Candidate subdomains saved to ${subs}"
  else
    warn "jq missing; skipping structured crt.sh parsing."
  fi

  cat <<EOF > "${CT_DIR}/${domain}.ct-tools.txt"
Manual CT sources to pivot:
- https://crt.sh/?q=%25${domain}
- https://search.censys.io/certificates?q=${domain}
- https://riddler.io/search?q=${domain}
- https://dnsdumpster.com/
EOF
}

# ---------- Phase 5: ASN / BGP ----------
recon_asn(){
  info "[PHASE 5] ASN and BGP scoping"
  build_bgp_toolkit_links
  bgpview_search_for_domains
  enrich_asns_from_ips
}

build_bgp_toolkit_links(){
  local file="${ASN_DIR}/${TARGET_DOMAIN}.bgp-he-links.md"
  {
    echo "# Hurricane Electric BGP Toolkit links"
    for domain in "${TARGET_DOMAINS[@]}"; do
      echo "- Search ${domain}: https://bgp.he.net/search?search%5Bsearch%5D=${domain}&commit=Search"
    done
    if [[ -n "${SEED_IP}" ]]; then
      echo "- Seed IP (${SEED_IP}): https://bgp.he.net/ip/${SEED_IP}"
    fi
    if [[ -n "${ASNS}" ]]; then
      echo
      echo "## Manual ASNs provided"
      IFS=',' read -r -a arr <<< "${ASNS}"
      for asn in "${arr[@]}"; do
        asn_trimmed=$(echo "$asn" | tr -d ' ')
        [[ -z "$asn_trimmed" ]] && continue
        echo "- ${asn_trimmed}: https://bgp.he.net/${asn_trimmed}"
      done
    fi
    if [[ -s "${ALL_ASNS_FILE}" ]]; then
      echo
      echo "## Auto-discovered ASNs"
      while read -r asn; do
        [[ -z "$asn" ]] && continue
        echo "- ${asn}: https://bgp.he.net/${asn}"
      done < "${ALL_ASNS_FILE}"
    fi
    if [[ -s "${ALL_PREFIXES_FILE}" ]]; then
      echo
      echo "## Auto-discovered prefixes"
      cat "${ALL_PREFIXES_FILE}"
    fi
  } > "${file}"
  ok "[PHASE 5] BGP Toolkit cheat sheet stored in ${file}"
}

bgpview_search_for_domains(){
  if ! command -v jq >/dev/null 2>&1; then
    warn "[PHASE 5] jq not available; skipping BGPView search API."
    return 0
  fi
  local output="${ASN_DIR}/bgpview-domain-search.txt"
  : > "${output}"
  while read -r domain; do
    [[ -z "$domain" ]] && continue
    local json="${ASN_DIR}/${domain}.bgpview-search.json"
    curl -s "https://api.bgpview.io/search?query_term=${domain}" -o "${json}" || { warn "BGPView search failed for ${domain}"; continue; }
    local asns prefixes
    asns=$(jq -r '.data.asns[].asn // empty' "${json}" 2>/dev/null || true)
    prefixes=$(jq -r '.data.prefixes[].prefix // empty' "${json}" 2>/dev/null || true)
    [[ -n "$asns" ]] && printf "## %s – ASNs\n%s\n\n" "${domain}" "${asns}" >> "${output}"
    [[ -n "$prefixes" ]] && printf "## %s – Prefixes\n%s\n\n" "${domain}" "${prefixes}" >> "${output}"
    while read -r asn; do
      [[ -z "$asn" ]] && continue
      record_unique_line "${ALL_ASNS_FILE}" "${asn}"
    done <<< "${asns}"
    while read -r prefix; do
      [[ -z "$prefix" ]] && continue
      record_unique_line "${ALL_PREFIXES_FILE}" "${prefix}"
    done <<< "${prefixes}"
  done < "${ALL_DOMAINS_FILE}"
  ok "[PHASE 5] BGPView domain search data saved to ${output}"
}

enrich_asns_from_ips(){
  if [[ ! -s "${ALL_IPS_FILE}" ]]; then
    warn "[PHASE 5] No IPs collected yet; skipping ASN enrichment."
    return 0
  fi
  if ! command -v jq >/dev/null 2>&1; then
    warn "[PHASE 5] jq not available; cannot parse BGPView IP data."
    return 0
  fi
  local summary="${ASN_DIR}/bgpview-ip-summary.txt"
  : > "${summary}"
  while read -r ip; do
    [[ -z "$ip" ]] && continue
    local json="${ASN_DIR}/${ip}.bgpview.json"
    curl -s "https://api.bgpview.io/ip/${ip}" -o "${json}" || { warn "BGPView IP lookup failed for ${ip}"; continue; }
    local asn asn_name
    asn=$(jq -r '.data.asn.asn // empty' "${json}" 2>/dev/null || true)
    asn_name=$(jq -r '.data.asn.name // empty' "${json}" 2>/dev/null || true)
    [[ -n "$asn" ]] && record_unique_line "${ALL_ASNS_FILE}" "${asn}"
    local prefixes
    prefixes=$(jq -r '.data.prefixes[].prefix // empty' "${json}" 2>/dev/null || true)
    while read -r prefix; do
      [[ -z "$prefix" ]] && continue
      record_unique_line "${ALL_PREFIXES_FILE}" "${prefix}"
    done <<< "${prefixes}"
    {
      echo "IP: ${ip}"
      echo "  ASN: ${asn:-Unknown} ${asn_name:+(${asn_name})}"
      echo "  Prefixes:"
      if [[ -n "$prefixes" ]]; then
        while read -r prefix; do
          [[ -z "$prefix" ]] && continue
          echo "    - ${prefix}"
        done <<< "${prefixes}"
      else
        echo "    - None reported by BGPView"
      fi
      echo "  ARIN Whois-RWS (manual): https://whois.arin.net/rest/ip/${ip}"
      echo
    } >> "${summary}"
  done < "${ALL_IPS_FILE}"
  ok "[PHASE 5] ASN/IP enrichment saved to ${summary}"
}

# ---------- Phase 6: AWS cloud ----------
recon_cloud_aws(){
  local domain="$1"
  [[ "$USE_CLOUD" -eq 1 ]] || { warn "[PHASE 6] AWS cloud module disabled (-C to enable)."; return 0; }
  if ! command -v jq >/dev/null 2>&1; then
    warn "[PHASE 6] jq not found; cannot parse AWS ip-ranges.json."
    return 0
  fi

  if [[ "${AWS_RANGES_READY}" -eq 0 ]]; then
    info "[PHASE 6] Downloading AWS ip-ranges.json"
    curl -s "https://ip-ranges.amazonaws.com/ip-ranges.json" -o "${AWS_RANGES_JSON}" || { warn "Failed to fetch AWS ranges"; return 0; }
    jq -r '.prefixes[] | [.region, .service, .ip_prefix] | @tsv' "${AWS_RANGES_JSON}" > "${CLOUD_DIR}/aws-ipv4-prefixes.tsv" || true
    AWS_RANGES_READY=1
  fi

  local ips
  ips=$(dig +short "${domain}" A | sort -u || true)
  if [[ -n "$ips" ]]; then
    local map_file="${CLOUD_DIR}/${domain}.aws-ip-mapping.tsv"
    {
      echo -e "ip\tmatching_prefix\tregion\tservice"
      while read -r ip; do
        [[ -z "$ip" ]] && continue
        echo -e "${ip}\t[use ipcalc against aws-ipv4-prefixes.tsv]\t?\t?"
      done <<< "${ips}"
    } > "${map_file}"
    ok "[PHASE 6] Cloud helper outputs stored in ${map_file}"
  else
    warn "[PHASE 6] No A records for ${domain}; skipping AWS mapping."
  fi
}

# ---------- Phase 7: Shodan ----------
generate_shodan_playbook(){
  local domain="$1"
  local cheat="${SHODAN_DIR}/${domain}.cheatsheet.txt"
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
  local domain="$1"
  [[ "$USE_SHODAN" -eq 1 ]] || { warn "[PHASE 7] Shodan module disabled (-S to enable)."; return 0; }
  info "[PHASE 7] Running base Shodan pivots for ${domain}"

  local q_org=""
  [[ -n "${COMPANY_NAME}" ]] && q_org="org:\"${COMPANY_NAME}\""

  local q1="ssl.cert.subject:\"${domain}\""
  local q2="hostname:\"${domain}\""
  local q_http="(ssl.cert.subject:\"${domain}\" OR hostname:\"${domain}\") port:80,443,8080,8443"
  local q_rdp="(ssl.cert.subject:\"${domain}\" OR hostname:\"${domain}\") port:3389"

  shodan search --fields ip_str,port,org,hostnames "${q1}" \
    > "${SHODAN_DIR}/${domain}.ssl-subject.txt" 2>&1 || warn "Shodan query ssl-subject failed for ${domain}"
  shodan search --fields ip_str,port,org,hostnames "${q2}" \
    > "${SHODAN_DIR}/${domain}.hostname.txt" 2>&1 || warn "Shodan query hostname failed for ${domain}"
  if [[ -n "${q_org}" ]]; then
    shodan search --fields ip_str,port,org,hostnames "${q_org}" \
      > "${SHODAN_DIR}/${domain}.org.txt" 2>&1 || warn "Shodan query org failed"
  fi
  shodan search --fields ip_str,port,org,hostnames,title "${q_http}" \
    > "${SHODAN_DIR}/${domain}.http-stack.txt" 2>&1 || warn "Shodan HTTP query failed for ${domain}"
  shodan search --fields ip_str,port,org,hostnames,os "${q_rdp}" \
    > "${SHODAN_DIR}/${domain}.rdp.txt" 2>&1 || warn "Shodan RDP query failed for ${domain}"

  generate_shodan_playbook "${domain}"
  ok "[PHASE 7] Shodan outputs ready for ${domain}."
}

emit_auto_shodan_queries(){
  local out="${SHODAN_DIR}/aggregated-queries.txt"
  if [[ ! -s "${ALL_ASNS_FILE}" && ! -s "${ALL_PREFIXES_FILE}" ]]; then
    warn "[PHASE 7] No ASNs or prefixes discovered; skipping auto-generated Shodan queries."
    return 0
  fi
  : > "${out}"
  {
    echo "# Shodan queries generated from auto-discovered ASNs / prefixes"
    if [[ -s "${ALL_ASNS_FILE}" ]]; then
      echo
      echo "## ASN filters"
      while read -r asn; do
        [[ -z "$asn" ]] && continue
        echo "shodan search 'asn:\"${asn}\"'"
      done < "${ALL_ASNS_FILE}"
    fi
    if [[ -s "${ALL_PREFIXES_FILE}" ]]; then
      echo
      echo "## net: filters"
      while read -r prefix; do
        [[ -z "$prefix" ]] && continue
        echo "shodan search 'net:\"${prefix}\"'"
      done < "${ALL_PREFIXES_FILE}"
    fi
  } >> "${out}"
  ok "[PHASE 7] Auto-generated Shodan query list saved to ${out}"
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

run_subfinder_pipeline(){
  [[ -n "${APEX_LIST_FILE}" ]] || return 0
  if [[ ! -f "${APEX_LIST_FILE}" ]]; then
    warn "[PHASE 8] Apex file ${APEX_LIST_FILE} not found; skipping subfinder/httpx pipeline."
    return 0
  fi
  if ! command -v subfinder >/dev/null 2>&1; then
    warn "[PHASE 8] subfinder not found; cannot run apex enumeration loop."
    return 0
  fi
  if ! command -v httpx >/dev/null 2>&1; then
    warn "[PHASE 8] httpx not found; cannot run apex enumeration loop."
    return 0
  fi
  local output_dir="${NOTES_DIR}/apex-httpx"
  mkdir -p "${output_dir}"
  info "[PHASE 8] Running subfinder → httpx loop using ${APEX_LIST_FILE}"
  while IFS= read -r apex; do
    apex="${apex%%#*}"
    apex="${apex//[$'\t\r\n ']/}"
    [[ -z "$apex" ]] && continue
    info "  [APEX] ${apex}"
    subfinder -d "${apex}" -all 2>/dev/null \
      | httpx -status-code -title -content-length -web-server -asn -location \
              -no-color -follow-redirects -t 15 \
              -ports 80,8080,443,8443,4443,8888 \
              -no-fallback -probe-all-ips -random-agent \
              -o "${output_dir}/${apex}.httpx.txt" -oa \
      || warn "subfinder/httpx pipeline failed for ${apex}"
  done < "${APEX_LIST_FILE}"
  ok "[PHASE 8] subfinder/httpx results stored in ${output_dir}"
}

# ---------- Phase 9: SpiderFoot HX ----------
plan_spiderfoot_osint(){
  [[ "$USE_SPIDERFOOT" -eq 1 ]] || return 0

  local file="${SPIDERFOOT_DIR}/${TARGET_DOMAIN}.spiderfoot-plan.md"
  info "[PHASE 9] Writing SpiderFoot HX plan"
  {
    cat <<EOF
# SpiderFoot HX playbook

- Console URL: ${SPIDERFOOT_URL:-https://spiderfoot.example.com}
- API key (if applicable): ${SPIDERFOOT_API_KEY:-<set-in-config>}
- Suggested modules: DNS, WHOIS, CT logs, Shodan, Censys, leaks, geography, paste sites.

## Suggested scan seeds
EOF
    for domain in "${TARGET_DOMAINS[@]}"; do
      echo "- Domain: ${domain}"
    done
    cat <<EOF2
- Company name: ${COMPANY_NAME:-N/A}
- Seed IP: ${SEED_IP:-N/A}
- ASNs: $(if [[ -s "${ALL_ASNS_FILE}" ]]; then paste -sd ',' "${ALL_ASNS_FILE}"; else echo "${ASNS:-N/A}"; fi)

## Workflow
1. Create a new scan titled "${TARGET_DOMAIN}-modern-recon".
2. Enable enrichment modules listed above plus any custom connectors available to your subscription tier.
3. Export results as JSON/CSV and place them in \`${SPIDERFOOT_DIR}/exports/\`.
4. Re-run this script's consolidation phase to merge SpiderFoot findings into asset lists.
EOF2
  } > "${file}"
  ok "[PHASE 9] SpiderFoot HX instructions stored at ${file}"
}

# ---------- Phase 10: Consolidation ----------
consolidate_assets(){
  info "[PHASE 10] Consolidating assets"
  mkdir -p "${REPORTS_DIR}"

  local domains_file="${REPORTS_DIR}/domains.txt"
  local subdomains_file="${REPORTS_DIR}/subdomains.txt"
  local ips_file="${REPORTS_DIR}/ips.txt"

  printf "%s\n" "${TARGET_DOMAINS[@]}" > "${domains_file}"
  [[ -n "${COMPANY_NAME}" ]] && printf "%s\n" "${COMPANY_NAME}" > "${REPORTS_DIR}/company.txt"

  : > "${subdomains_file}"
  for domain in "${TARGET_DOMAINS[@]}"; do
    [[ -f "${CT_DIR}/${domain}.subdomains.txt" ]] && cat "${CT_DIR}/${domain}.subdomains.txt" >> "${subdomains_file}"
    [[ -f "${SNI_DIR}/${domain}.sni-hosts.txt" ]] && cat "${SNI_DIR}/${domain}.sni-hosts.txt" >> "${subdomains_file}"
  done
  sort -u "${subdomains_file}" -o "${subdomains_file}" || true

  if [[ -s "${ALL_IPS_FILE}" ]]; then
    sort -u "${ALL_IPS_FILE}" -o "${ALL_IPS_FILE}" || true
    cp "${ALL_IPS_FILE}" "${ips_file}"
  else
    : > "${ips_file}"
  fi

  [[ -s "${ALL_ASNS_FILE}" ]] && cp "${ALL_ASNS_FILE}" "${REPORTS_DIR}/asns.txt"
  [[ -s "${ALL_PREFIXES_FILE}" ]] && cp "${ALL_PREFIXES_FILE}" "${REPORTS_DIR}/prefixes.txt"

  {
    echo "# Recon consolidation"
    echo "- Domains: ${domains_file}"
    echo "- Subdomains: ${subdomains_file}"
    echo "- IPs: ${ips_file}"
    echo "- ASNs: ${REPORTS_DIR}/asns.txt"
    echo "- Prefixes: ${REPORTS_DIR}/prefixes.txt"
    echo "- Shodan cheat sheets: ${SHODAN_DIR}"
    echo "- SpiderFoot plan: ${SPIDERFOOT_DIR}/${TARGET_DOMAIN}.spiderfoot-plan.md"
  } > "${REPORTS_DIR}/README.txt"

  ok "[PHASE 10] Asset lists generated under reports/."
}

# ---------- Summary ----------
print_summary(){
  echo
  echo -e "${C_BLU}===================== SUMMARY =====================${C_RST}"
  echo "Targets:"
  for domain in "${TARGET_DOMAINS[@]}"; do
    echo "  - ${domain}"
  done
  [[ -n "${COMPANY_NAME}" ]] && echo "Company:       ${COMPANY_NAME}"
  [[ -n "${SEED_IP}" ]] && echo "Seed IP:       ${SEED_IP}"
  [[ -n "${ASNS}" ]] && echo "Manual ASNs:   ${ASNS}"
  echo "Output path:   ${OUTDIR}"
  if [[ -s "${ALL_IPS_FILE}" ]]; then
    echo "Resolved IPs:  $(wc -l < "${ALL_IPS_FILE}" 2>/dev/null) stored in ${ALL_IPS_FILE}"
  fi
  if [[ -s "${ALL_ASNS_FILE}" ]]; then
    echo "Auto ASNs:     $(wc -l < "${ALL_ASNS_FILE}" 2>/dev/null) stored in ${ALL_ASNS_FILE}"
  fi
  if [[ -s "${ALL_PREFIXES_FILE}" ]]; then
    echo "Auto prefixes: $(wc -l < "${ALL_PREFIXES_FILE}" 2>/dev/null) stored in ${ALL_PREFIXES_FILE}"
  fi
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
      TARGET_DOMAINS+=("$2"); shift 2;;
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
    -A|--apex-file)
      APEX_LIST_FILE="$2"; shift 2;;
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

if ((${#TARGET_DOMAINS[@]} == 0)); then
  usage
  die "You must specify -d / --domain"
fi
TARGET_DOMAIN="${TARGET_DOMAINS[0]}"
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
info "Launching hadixxity.sh – Modern Recon for: ${TARGET_DOMAINS[*]}"

capture_corporate_intel
for domain in "${TARGET_DOMAINS[@]}"; do
  recon_whois "${domain}"
  recon_dns "${domain}"
  recon_ct "${domain}"
  recon_cloud_aws "${domain}"
  recon_shodan "${domain}"
done
recon_asn
emit_auto_shodan_queries
plan_spiderfoot_osint
run_subfinder_pipeline

warn "[PHASE 8] Reminder: drop your TLS/SNI scanner outputs into ${SNI_DIR}"
warn "             then run: process_sni_outputs \"${TARGET_DOMAINS[0]}\""

consolidate_assets
print_summary
ok "hadixxity.sh completed."

exit 0

