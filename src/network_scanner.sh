#!/bin/bash
################################################################################
# Ford & Olsen - IT 359 Project: Automated Network Scanner
# Version: 3.2 - Per-Scan Folders + Per-Scan Alerts + Zipped Outputs + Cleanup
#
# Description:
#   - Beginner-friendly guided mode with prompts for target, tools, flags, etc.
#   - Advanced one-line mode where power users can specify everything at once:
#         10.10.10.10 | tools=nmap,masscan,netcat | nmap=-sV -p- --open \
#                      | masscan=-p0-65535 --rate=5000 | netcat=22,80,443 \
#                      | format=text,html | verbose=1
#   - Supports multiple output formats (text, CSV, HTML) at once.
#   - For EVERY scan:
#       * A dedicated folder is created: scan_<target>_<timestamp>/
#       * A per-scan alerts.log is created inside that folder.
#       * One or more report files are generated inside that folder.
#       * The folder is zipped to scan_<target>_<timestamp>.zip.
#       * After successful zip, the original folder is deleted to conserve space.
################################################################################

set -euo pipefail
# -e  : exit on any non-zero command
# -u  : treat unset variables as an error
# -o pipefail : pipeline fails if any command in it fails

################################################################################
# Color codes for output (for nicer terminal UI)
################################################################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

################################################################################
# Global variables
################################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/scan_reports"   # All reports stored here
TEMP_DIR="/tmp/network_scanner_$$"        # Per-run temp directory

REPORT_FORMAT="text"                      # Default format (can become "text,csv", etc.)
TARGET=""
TOOLS_ARRAY=()                            # e.g., ("nmap" "masscan" "netcat")
NMAP_FLAGS=""
MASSCAN_FLAGS=""
NETCAT_FLAGS=""
VERBOSE=false

# Per-scan metadata (set after config is confirmed)
SAFE_TARGET=""
SCAN_TS=""
SCAN_DIR=""
ALERT_LOG=""                              # Per-scan alerts.log path

################################################################################
# Utility Functions (printing, logging, cleanup)
################################################################################

print_header() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   Automated Network Scanner - IT 359       ║${NC}"
    echo -e "${BLUE}║   Ford & Olsen                             ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
    echo ""
}

print_info() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[X]${NC} $1"
}

print_alert() {
    echo -e "${RED}[ALERT]${NC} $1"
    log_alert "$1"
}

print_section() {
    echo ""
    echo -e "${CYAN}▶ $1${NC}"
    echo -e "${CYAN}$(printf '─%.0s' {1..50})${NC}"
}

log_alert() {
    # Append alert with timestamp to the per-scan alerts.log if it's set
    [[ -n "$ALERT_LOG" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$ALERT_LOG"
}

cleanup() {
    [[ -d "${TEMP_DIR}" ]] && rm -rf "${TEMP_DIR}"
}

trap cleanup EXIT

################################################################################
# Validation Functions (dependencies, target)
################################################################################

check_dependencies() {
    local missing_tools=()
    # Debian/Ubuntu usually provide netcat as "nc" (netcat-openbsd)
    for tool in nmap nc masscan; do
        command -v "$tool" &>/dev/null || missing_tools+=("$tool")
    done
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        print_info "Install with: sudo apt-get install nmap netcat-openbsd masscan"
        exit 1
    fi
}

validate_target() {
    local target="$1"
    # IPv4 (with optional /CIDR) OR hostname regex
    if ! [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]] && \
       ! [[ "$target" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        print_error "Invalid target format: $target"
        return 1
    fi
    return 0
}

################################################################################
# Advanced Input Parsing (for one-line advanced mode)
################################################################################

# Parses segments like:
#   tools=nmap,masscan,netcat
#   nmap=-sV -p- --open
#   masscan=-p0-65535 --rate=5000
#   netcat=22,80,443
#   format=text,html or format=all
#   verbose=1
parse_advanced_options_from_segments() {
    local seg key val
    for seg in "$@"; do
        seg="$(echo "$seg" | xargs)"
        [[ -z "$seg" ]] && continue
        [[ "$seg" != *=* ]] && continue

        key="${seg%%=*}"
        val="${seg#*=}"

        # Strip possible surrounding quotes
        val="${val%\"}"; val="${val#\"}"
        val="${val%\'}"; val="${val#\'}"

        case "$key" in
            tools)
                TOOLS_ARRAY=()
                IFS=',' read -ra TOOLS_ARRAY <<< "$val"
                ;;
            nmap|nmap_flags)
                NMAP_FLAGS="$val"
                ;;
            masscan|masscan_flags)
                MASSCAN_FLAGS="$val"
                ;;
            netcat|netcat_ports)
                NETCAT_FLAGS="$val"
                ;;
            format)
                val="${val//[[:space:]]/}"
                if [[ "$val" == "all" ]]; then
                    REPORT_FORMAT="all"
                else
                    REPORT_FORMAT="$val"
                fi
                ;;
            verbose)
                case "$val" in
                    1|true|yes|on|Y|y) VERBOSE=true ;;
                esac
                ;;
        esac
    done
}

################################################################################
# Interactive Prompt Functions
################################################################################

prompt_target() {
    print_section "Target Configuration"

    echo "Beginner mode:"
    echo "  Just type an IP or hostname and press Enter."
    echo "  Example: 10.10.10.10"
    echo
    echo "Advanced one-line mode (optional):"
    echo "  Use '|' to add tools, flags, and options on the same line."
    echo "  Example:"
    echo "    10.10.10.10 | tools=nmap,masscan,netcat | nmap=-sV -p- --open \\"
    echo "                 | masscan=-p0-65535 --rate=5000 | netcat=22,80,443 \\"
    echo "                 | format=text,html | verbose=1"
    echo

    while true; do
        read -r -p "Enter target (and optional advanced options): " line
        [[ -z "$line" ]] && { print_error "Input cannot be empty"; continue; }

        IFS='|' read -r -a segments <<< "$line"

        local tgt="${segments[0]}"
        tgt="$(echo "$tgt" | xargs)"

        if ! validate_target "$tgt"; then
            print_error "Invalid format. Use IP (e.g. 192.168.1.1) or hostname (e.g. example.com)"
            continue
        fi

        TARGET="$tgt"
        print_info "Target set to: $TARGET"

        if (( ${#segments[@]} > 1 )); then
            parse_advanced_options_from_segments "${segments[@]:1}"

            [[ ${#TOOLS_ARRAY[@]} -gt 0 ]] && print_info "Advanced tools set: ${TOOLS_ARRAY[*]}"
            [[ -n "$NMAP_FLAGS" ]]    && print_info "Advanced nmap flags set"
            [[ -n "$MASSCAN_FLAGS" ]] && print_info "Advanced masscan flags set"
            [[ -n "$NETCAT_FLAGS" ]]  && print_info "Advanced netcat ports set"
            [[ "$REPORT_FORMAT" != "text" ]] && print_info "Advanced report format: $REPORT_FORMAT"
            $VERBOSE && print_info "Advanced verbose mode enabled"
        fi

        break
    done
}

prompt_tools() {
    print_section "Select Scanning Tools"
    echo "1) nmap     - comprehensive port scanning & service detection"
    echo "2) masscan  - fast port scanner (needs sudo)"
    echo "3) netcat   - probe specific ports"
    echo "4) all three tools"
    read -p "Select [1-4]: " c
    case "$c" in
        1) TOOLS_ARRAY=("nmap") ;;
        2) TOOLS_ARRAY=("masscan") ;;
        3) TOOLS_ARRAY=("netcat") ;;
        4) TOOLS_ARRAY=("nmap" "masscan" "netcat") ;;
        *) print_error "Invalid selection"; prompt_tools; return ;;
    esac
    print_info "Selected tools: ${TOOLS_ARRAY[*]}"
}

prompt_nmap_flags() {
    print_section "Configure Nmap Scan"
    echo "1) Full port scan with service detection (slow)"
    echo "2) Top 1000 ports + service detection (balanced)"
    echo "3) Common ports only (fast) – 20,21,22,23,25,53,80,443,3306,5432,8080"
    echo "4) Custom flags"
    read -p "Choose [1-4]: " c
    case "$c" in
        1) NMAP_FLAGS="-sV -sC -p- --open" ;;
        2) NMAP_FLAGS="-sV -sC --open" ;;
        3) NMAP_FLAGS="-sV -p 20,21,22,23,25,53,80,443,3306,5432,8080 --open" ;;
        4) read -p "Enter custom nmap flags: " NMAP_FLAGS ;;
        *) print_error "Invalid"; prompt_nmap_flags; return ;;
    esac
    print_info "Nmap flags: $NMAP_FLAGS"
}

prompt_masscan_flags() {
    print_section "Configure Masscan Scan"
    read -p "Port range [0-65535]: " pr
    pr=${pr:-0-65535}
    read -p "Rate (pkts/sec) [1000]: " rt
    rt=${rt:-1000}
    MASSCAN_FLAGS="-p$pr --rate=$rt"
    print_info "Masscan flags: $MASSCAN_FLAGS"
}

prompt_netcat_flags() {
    print_section "Configure Netcat Probing"
    read -p "Ports to probe [22,80,443,3306,5432,8080,8443]: " pts
    NETCAT_FLAGS="${pts:-22,80,443,3306,5432,8080,8443}"
    print_info "Netcat ports: $NETCAT_FLAGS"
}

prompt_output_format() {
    print_section "Report Output Format"
    echo "Choose one or multiple (comma-separated):"
    echo "  1) Text"
    echo "  2) CSV"
    echo "  3) HTML"
    echo "  4) All (Text + CSV + HTML)"
    read -p "Choose [1-4] (e.g., 1 or 1,3 or 1,2,3): " c

    c="${c//[[:space:]]/}"

    if [[ -z "$c" ]]; then
        print_error "No selection made."
        prompt_output_format
        return
    fi

    if [[ "$c" == "4" || "$c" == "all" || "$c" == "ALL" ]]; then
        REPORT_FORMAT="all"
        print_info "Report formats: Text, CSV, HTML (all)"
        return
    fi

    IFS=',' read -r -a choices <<< "$c"
    local formats=()
    local seen_text=0 seen_csv=0 seen_html=0

    for ch in "${choices[@]}"; do
        case "$ch" in
            1)
                (( seen_text == 0 )) && { formats+=("text"); seen_text=1; }
                ;;
            2)
                (( seen_csv == 0 )) && { formats+=("csv"); seen_csv=1; }
                ;;
            3)
                (( seen_html == 0 )) && { formats+=("html"); seen_html=1; }
                ;;
            *)
                print_warning "Ignoring invalid format option: $ch"
                ;;
        esac
    done

    if (( ${#formats[@]} == 0 )); then
        print_error "No valid format options selected."
        prompt_output_format
        return
    fi

    REPORT_FORMAT="${formats[0]}"
    if (( ${#formats[@]} > 1 )); then
        for ((i=1; i<${#formats[@]}; i++)); do
            REPORT_FORMAT+=",${formats[i]}"
        done
    fi

    print_info "Report formats: $REPORT_FORMAT"
}

prompt_verbose() {
    print_section "Verbosity"
    read -p "Verbose output? [y/N]: " v
    [[ "$v" =~ ^[Yy]$ ]] && VERBOSE=true
}

print_summary() {
    print_section "Scan Configuration Summary"
    echo "Target : $TARGET"
    echo "Tools  : ${TOOLS_ARRAY[*]}"
    echo "Format : $REPORT_FORMAT"
    [[ " ${TOOLS_ARRAY[*]} " == *" nmap "* ]]    && echo "Nmap   : $NMAP_FLAGS"
    [[ " ${TOOLS_ARRAY[*]} " == *" masscan "* ]] && echo "Masscan: $MASSCAN_FLAGS"
    [[ " ${TOOLS_ARRAY[*]} " == *" netcat "* ]]  && echo "Netcat : $NETCAT_FLAGS"
    echo "Verbose: $VERBOSE"
    read -p "Start scan? [y/N]: " c
    [[ "$c" =~ ^[Yy]$ ]] && return 0
    print_warning "Cancelled – restarting config…"
    return 1
}

################################################################################
# Scanning Functions
################################################################################

run_nmap_scan() {
    local tgt="$1" out="${TEMP_DIR}/nmap_results.txt"
    print_info "Running nmap on $tgt"
    $VERBOSE && print_info "nmap $NMAP_FLAGS $tgt"
    # shellcheck disable=SC2086
    nmap $NMAP_FLAGS "$tgt" >"$out" 2>&1 || true
    print_info "Nmap complete"
    $VERBOSE && cat "$out"
}

run_masscan_scan() {
    local tgt="$1" out="${TEMP_DIR}/masscan_results.txt"
    print_info "Running masscan on $tgt (requires sudo)"
    $VERBOSE && print_info "sudo masscan $tgt $MASSCAN_FLAGS"
    # shellcheck disable=SC2086
    sudo masscan "$tgt" $MASSCAN_FLAGS -oL "$out" 2>&1 || true
    print_info "Masscan complete"
    $VERBOSE && { grep "^open" "$out" || print_warning "No open ports"; }
}

run_netcat_probe() {
    local tgt="$1" out="${TEMP_DIR}/netcat_results.txt"
    print_info "Netcat probing on $tgt"
    >"$out"
    IFS=',' read -ra PTS <<<"$NETCAT_FLAGS"
    for p in "${PTS[@]}"; do
        p=$(echo "$p" | xargs)
        $VERBOSE && print_info "Probing port $p"
        timeout 2 nc -zv "$tgt" "$p" >>"$out" 2>&1 && print_info "Port $p open"
    done
    print_info "Netcat complete"
    $VERBOSE && cat "$out"
}

################################################################################
# Analysis & Alerts
################################################################################

analyze_results() {
    print_section "Analysis & Alerts"
    local nf="${TEMP_DIR}/nmap_results.txt"
    [[ -f $nf ]] || return

    grep -q "22/tcp.*open"  "$nf" && print_alert "SSH exposed (22)"
    grep -E "80/tcp.*open|443/tcp.*open" "$nf" && print_alert "Web service (80/443)"
    grep -E "3306|5432|27017" "$nf" && print_alert "Database port detected"

    local c
    c=$(grep -c "open" "$nf" || true)
    (( c > 5 )) && print_alert "High port count: $c"
}

################################################################################
# Report Generation: Text & CSV
################################################################################

generate_text_report() {
    local out="$1"
    {
        echo "═════════════════════════════════════════════════"
        echo "Network Reconnaissance Report"
        echo "Target: $TARGET"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Tools: ${TOOLS_ARRAY[*]}"
        echo "═════════════════════════════════════════════════"
        echo
        for f in nmap netcat masscan; do
            [[ -f "${TEMP_DIR}/${f}_results.txt" ]] || continue
            echo "=== ${f^^} Results ==="
            cat "${TEMP_DIR}/${f}_results.txt"
            echo
        done
    } >"$out"
}

generate_csv_report() {
    local out="$1"
    {
        echo "Tool,Host,Protocol,Port,State,Service,Version/Info,RiskLevel,Category"

        # Nmap
        if [[ -f "${TEMP_DIR}/nmap_results.txt" ]]; then
            grep -E '^[0-9]+/(tcp|udp)[[:space:]]+open' "${TEMP_DIR}/nmap_results.txt" | \
            awk -v host="$TARGET" 'BEGIN{OFS=","}
            {
                port_proto=$1
                state=$2
                service=$3

                port=port_proto
                proto=port_proto

                sub(/\/.*/, "", port)
                sub(/^[0-9]+\//, "", proto)

                version=""
                if (NF > 3) {
                    version=$4
                    for (i=5; i<=NF; i++) {
                        version=version" "$i
                    }
                }

                risk="Low"
                category="Other"
                if (port=="21" || port=="22" || port=="23" || port=="25" || port=="445" || port=="3389" || port=="139") {
                    risk="High"
                    category="Admin/Remote Access"
                } else if (port=="80" || port=="443" || port=="8080" || port=="8443") {
                    risk="Medium"
                    category="Web Service"
                } else if (port=="3306" || port=="5432" || port=="1433" || port=="27017") {
                    risk="Medium"
                    category="Database"
                }

                gsub(/,/, " ", version)
                gsub(/,/, " ", service)

                print "nmap",host,proto,port,state,service,version,risk,category
            }' || true
        fi

        # Masscan
        if [[ -f "${TEMP_DIR}/masscan_results.txt" ]]; then
            grep '^open' "${TEMP_DIR}/masscan_results.txt" | \
            awk 'BEGIN{OFS=","}
            {
                state=$1
                proto=$2
                port=$3
                host=$4

                risk="Low"
                category="Other"
                if (port=="21" || port=="22" || port=="23" || port=="25" || port=="445" || port=="3389" || port=="139") {
                    risk="High"
                    category="Admin/Remote Access"
                } else if (port=="80" || port=="443" || port=="8080" || port=="8443") {
                    risk="Medium"
                    category="Web Service"
                } else if (port=="3306" || port=="5432" || port=="1433" || port=="27017") {
                    risk="Medium"
                    category="Database"
                }

                print "masscan",host,proto,port,state,"","",risk,category
            }' || true
        fi

        # Netcat
        if [[ -f "${TEMP_DIR}/netcat_results.txt" ]]; then
            grep -i 'succeeded' "${TEMP_DIR}/netcat_results.txt" | \
            awk 'BEGIN{OFS=","}
            {
                host=$3
                port=$4
                proto_field=$6
                gsub(/\[|\]/, "", proto_field)
                split(proto_field,a,"/")
                proto=a[1]
                service=""
                if (length(a) > 1) {
                    service=a[2]
                }

                risk="Low"
                category="Other"
                if (port=="21" || port=="22" || port=="23" || port=="25" || port=="445" || port=="3389" || port=="139") {
                    risk="High"
                    category="Admin/Remote Access"
                } else if (port=="80" || port=="443" || port=="8080" || port=="8443" ||
                           port=="3306" || port=="5432" || port=="1433" || port=="27017") {
                    risk="Medium"
                    category="Database"
                }

                gsub(/,/, " ", service)

                print "netcat",host,proto,port,"open",service,"",risk,category
            }' || true
        fi
    } >"$out"
}

################################################################################
# HTML Report Helpers
################################################################################

html_escape() {
    sed -e 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

generate_html_report() {
    local out="$1"
    local total_open=0 high_risk_count=0 web_count=0 db_count=0
    local nmap_rows="" masscan_rows="" netcat_rows=""
    local nmap_raw="" masscan_raw="" netcat_raw=""

    # Nmap stats + rows
    if [[ -f "${TEMP_DIR}/nmap_results.txt" ]]; then
        total_open=$(grep -c "open" "${TEMP_DIR}/nmap_results.txt" || true)
        high_risk_count=$(grep -Ec '^(21|22|23|25|445|3389|139)/tcp[[:space:]]+open' "${TEMP_DIR}/nmap_results.txt" || true)
        web_count=$(grep -Ec '^(80|443|8080|8443)/tcp[[:space:]]+open' "${TEMP_DIR}/nmap_results.txt" || true)
        db_count=$(grep -Ec '^(3306|5432|1433|27017)/tcp[[:space:]]+open' "${TEMP_DIR}/nmap_results.txt" || true)

        nmap_rows=$(grep -E '^[0-9]+/(tcp|udp)[[:space:]]+open' "${TEMP_DIR}/nmap_results.txt" | \
            awk '
            {
                port_proto=$1
                state=$2
                service=$3

                port=port_proto
                proto=port_proto

                sub(/\/.*/, "", port)
                sub(/^[0-9]+\//, "", proto)

                version=""
                if (NF > 3) {
                    version=$4
                    for (i=5; i<=NF; i++) {
                        version=version" "$i
                    }
                }

                risk="risk-low"
                if (port=="21" || port=="22" || port=="23" || port=="25" || port=="445" || port=="3389" || port=="139") {
                    risk="risk-high"
                } else if (port=="80" || port=="443" || port=="8080" || port=="8443" ||
                           port=="3306" || port=="5432" || port=="1433" || port=="27017") {
                    risk="risk-medium"
                }

                gsub(/&/, "\\&amp;", version)
                gsub(/</, "\\&lt;", version)
                gsub(/>/, "\\&gt;", version)
                gsub(/&/, "\\&amp;", service)
                gsub(/</, "\\&lt;", service)
                gsub(/>/, "\\&gt;", service)

                printf "<tr class=\"%s\"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
                       risk, port, proto, state, service, version
            }' || true)
        nmap_raw=$(html_escape < "${TEMP_DIR}/nmap_results.txt")
    fi

    # Masscan HTML rows
    if [[ -f "${TEMP_DIR}/masscan_results.txt" ]]; then
        masscan_rows=$(grep '^open' "${TEMP_DIR}/masscan_results.txt" | \
            awk '
            {
                state=$1
                proto=$2
                port=$3
                host=$4

                risk="risk-low"
                if (port=="21" || port=="22" || port=="23" || port=="25" || port=="445" || port=="3389" || port=="139") {
                    risk="risk-high"
                } else if (port=="80" || port=="443" || port=="8080" || port=="8443" ||
                           port=="3306" || port=="5432" || port=="1433" || port=="27017") {
                    risk="risk-medium"
                }

                printf "<tr class=\"%s\"><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
                       risk, host, proto, port, state
            }' || true)
        masscan_raw=$(html_escape < "${TEMP_DIR}/masscan_results.txt")
    fi

    # Netcat HTML rows
    if [[ -f "${TEMP_DIR}/netcat_results.txt" ]]; then
        netcat_rows=$(grep -i 'succeeded' "${TEMP_DIR}/netcat_results.txt" | \
            awk '
            {
                host=$3
                port=$4
                proto_field=$6
                gsub(/\[|\]/, "", proto_field)
                split(proto_field,a,"/")
                proto=a[1]
                service=""
                if (length(a) > 1) {
                    service=a[2]
                }

                risk="risk-low"
                if (port=="21" || port=="22" || port=="23" || port=="25" || port=="445" || port=="3389" || port=="139") {
                    risk="risk-high"
                } else if (port=="80" || port=="443" || port=="8080" || port=="8443" ||
                           port=="3306" || port=="5432" || port=="1433" || port=="27017") {
                    risk="risk-medium"
                }

                printf "<tr class=\"%s\"><td>%s</td><td>%s</td><td>%s</td><td>open</td><td>%s</td></tr>\n",
                       risk, host, proto, port, service
            }' || true)
        netcat_raw=$(html_escape < "${TEMP_DIR}/netcat_results.txt")
    fi

    local nmap_section="" masscan_section="" netcat_section=""

    nmap_section+="<h2>Nmap Summary</h2>"
    if [[ -n "$nmap_rows" ]]; then
        nmap_section+="
<table>
  <thead>
    <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr>
  </thead>
  <tbody>
${nmap_rows}
  </tbody>
</table>"
    else
        nmap_section+="<p>No parsed Nmap results available.</p>"
    fi
    if [[ -n "$nmap_raw" ]]; then
        nmap_section+="
<details>
  <summary>Show raw Nmap output</summary>
  <pre>${nmap_raw}</pre>
</details>"
    fi

    masscan_section+="<h2>Masscan Summary</h2>"
    if [[ -n "$masscan_rows" ]]; then
        masscan_section+="
<table>
  <thead>
    <tr><th>Host</th><th>Protocol</th><th>Port</th><th>State</th></tr>
  </thead>
  <tbody>
${masscan_rows}
  </tbody>
</table>"
    else
        masscan_section+="<p>No parsed Masscan results available.</p>"
    fi
    if [[ -n "$masscan_raw" ]]; then
        masscan_section+="
<details>
  <summary>Show raw Masscan output</summary>
  <pre>${masscan_raw}</pre>
</details>"
    fi

    netcat_section+="<h2>Netcat Summary</h2>"
    if [[ -n "$netcat_rows" ]]; then
        netcat_section+="
<table>
  <thead>
    <tr><th>Host</th><th>Protocol</th><th>Port</th><th>State</th><th>Service</th></tr>
  </thead>
  <tbody>
${netcat_rows}
  </tbody>
</table>"
    else
        netcat_section+="<p>No parsed Netcat results available.</p>"
    fi
    if [[ -n "$netcat_raw" ]]; then
        netcat_section+="
<details>
  <summary>Show raw Netcat output</summary>
  <pre>${netcat_raw}</pre>
</details>"
    fi

    local risk_message=""
    if (( high_risk_count > 0 )); then
        risk_message="High-risk services (like SSH, RDP, SMB, FTP, Telnet) are exposed. These should usually be restricted to trusted admin networks or protected by VPN/firewall rules."
    else
        risk_message="No classic high-risk admin ports were detected as open, but you should still review the exposed services below."
    fi

    local web_message=""
    if (( web_count > 0 )); then
        web_message="Web services are exposed (HTTP/HTTPS). Make sure they are patched and properly configured (TLS, strong passwords, no default logins)."
    else
        web_message="No common web ports were detected as open by Nmap."
    fi

    local db_message=""
    if (( db_count > 0 )); then
        db_message="Database services are reachable over the network. Databases should rarely be exposed directly to the internet."
    else
        db_message="No common database ports were detected as open by Nmap."
    fi

    cat > "$out" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Scan Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:40px;background:#f9f9f9;}
.container{background:#fff;padding:30px;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,.1);}
h1{color:#333;}
h2{margin-top:30px;color:#444;}
table{border-collapse:collapse;width:100%;margin-top:10px;}
th,td{border:1px solid #ccc;padding:6px 8px;font-size:14px;text-align:left;}
th{background:#f0f0f0;}
pre{background:#eee;padding:10px;border-radius:4px;overflow-x:auto;}
details summary{cursor:pointer;font-weight:bold;margin-top:10px;}
.summary-box{
  background:#f5f9ff;
  border-left:4px solid #3498db;
  padding:10px 12px;
  margin:15px 0;
  border-radius:4px;
}
.badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:12px;color:#fff;margin-right:8px;}
.badge-high{background:#e74c3c;}
.badge-medium{background:#f39c12;}
.badge-low{background:#16a085;}
.risk-high td{background:#ffe5e5;}
.risk-medium td{background:#fff4e0;}
.risk-low td{background:#e8f8f5;}
.small-note{font-size:12px;color:#666;margin-top:5px;}
</style>
</head>
<body>
<div class="container">
  <h1>Network Scan Report</h1>
  <p><strong>Target:</strong> ${TARGET}</p>
  <p><strong>Scan Date:</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>

  <div class="summary-box">
    <h2>Executive Summary (Beginner Friendly)</h2>
    <ul>
      <li><strong>Total open ports detected by Nmap:</strong> ${total_open}</li>
      <li><strong>High-risk services (SSH/RDP/SMB/FTP/Telnet/etc.):</strong> ${high_risk_count}</li>
      <li><strong>Web services (HTTP/HTTPS/Alt-Web):</strong> ${web_count}</li>
      <li><strong>Database services:</strong> ${db_count}</li>
    </ul>
    <p>${risk_message}</p>
    <p>${web_message}</p>
    <p>${db_message}</p>
    <p class="small-note">
      Color legend:
      <span class="badge badge-high">High-risk</span>
      <span class="badge badge-medium">Medium-risk</span>
      <span class="badge badge-low">Lower-risk</span>
      — beginners can start by reviewing the red rows first.
    </p>
  </div>

  <hr/>
  ${nmap_section}
  <hr/>
  ${masscan_section}
  <hr/>
  ${netcat_section}
</div>
</body>
</html>
EOF

    print_info "HTML report generated: $out"
}

################################################################################
# Multi-format Handling (per-scan folder + alerts + zip + cleanup)
################################################################################

generate_selected_reports() {
    print_section "Generating Reports"

    local base="${SCAN_DIR}/report_${SAFE_TARGET}_${SCAN_TS}"

    if [[ "$REPORT_FORMAT" == "all" ]]; then
        generate_text_report "${base}.txt"
        generate_csv_report  "${base}.csv"
        generate_html_report "${base}.html"
        print_info "Generated all report types in: $SCAN_DIR"
    else
        IFS=',' read -r -a fmts <<< "$REPORT_FORMAT"
        for f in "${fmts[@]}"; do
            case "$f" in
                text)
                    generate_text_report "${base}.txt"
                    print_info "Text report: ${base}.txt"
                    ;;
                csv)
                    generate_csv_report "${base}.csv"
                    print_info "CSV report : ${base}.csv"
                    ;;
                html)
                    generate_html_report "${base}.html"
                    print_info "HTML report: ${base}.html"
                    ;;
                *)
                    print_warning "Unknown report format: $f (skipped)"
                    ;;
            esac
        done
    fi

    # Zip SCAN_DIR and then remove SCAN_DIR to conserve space
    if command -v zip >/dev/null 2>&1; then
        local zip_name="scan_${SAFE_TARGET}_${SCAN_TS}.zip"
        (
            cd "$OUTPUT_DIR" && \
            zip -rq "$zip_name" "scan_${SAFE_TARGET}_${SCAN_TS}"
        )
        if [[ -f "${OUTPUT_DIR}/${zip_name}" ]]; then
            print_info "Zipped scan folder: ${OUTPUT_DIR}/${zip_name}"
            rm -rf "$SCAN_DIR"
            print_info "Removed original folder: $SCAN_DIR (zip retained)"
        else
            print_warning "Zip file not created; keeping directory: $SCAN_DIR"
        fi
    else
        print_warning "zip command not found; reports stored uncompressed in: ${SCAN_DIR}"
    fi

    print_info "Alerts were logged to: $ALERT_LOG"
}

################################################################################
# Main
################################################################################

main() {
    print_header
    check_dependencies
    mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"

    # 1) Target (+ optional advanced options)
    prompt_target

    # 2) Tools (if not set by advanced options)
    if [[ ${#TOOLS_ARRAY[@]} -eq 0 ]]; then
        prompt_tools
    fi

    # 3) Flags (prompt only if not set in advanced mode)
    for t in "${TOOLS_ARRAY[@]}"; do
        case "$t" in
            nmap)
                [[ -z "$NMAP_FLAGS" ]] && prompt_nmap_flags
                ;;
            masscan)
                [[ -z "$MASSCAN_FLAGS" ]] && prompt_masscan_flags
                ;;
            netcat)
                [[ -z "$NETCAT_FLAGS" ]] && prompt_netcat_flags
                ;;
        esac
    done

    # 4) Output format (if not overridden)
    if [[ "$REPORT_FORMAT" == "text" ]]; then
        prompt_output_format
    fi

    # 5) Verbose (if not already enabled)
    if ! $VERBOSE; then
        prompt_verbose
    fi

    # Confirm config; allow re-selection if cancelled
    while ! print_summary; do
        print_header
        prompt_tools
        for t in "${TOOLS_ARRAY[@]}"; do
            case "$t" in
                nmap)    prompt_nmap_flags ;;
                masscan) prompt_masscan_flags ;;
                netcat)  prompt_netcat_flags ;;
            esac
        done
    done

    # Per-scan folder and alerts.log setup
    SAFE_TARGET=$(echo "$TARGET" | tr '/:' '_')
    SCAN_TS=$(date '+%Y%m%d_%H%M%S')
    SCAN_DIR="${OUTPUT_DIR}/scan_${SAFE_TARGET}_${SCAN_TS}"
    mkdir -p "$SCAN_DIR"

    ALERT_LOG="${SCAN_DIR}/alerts.log"
    touch "$ALERT_LOG"
    print_info "Per-scan folder: $SCAN_DIR"
    print_info "Per-scan alert log: $ALERT_LOG"

    # Run scans
    print_header
    print_section "Starting Network Reconnaissance"

    for t in "${TOOLS_ARRAY[@]}"; do
        case "$t" in
            nmap)    run_nmap_scan "$TARGET" ;;
            masscan) run_masscan_scan "$TARGET" ;;
            netcat)  run_netcat_probe "$TARGET" ;;
        esac
        echo
    done

    # Analysis + reports + zip + cleanup
    analyze_results
    generate_selected_reports

    print_section "Scan Complete"
    print_info "Zipped scan reports are stored under: $OUTPUT_DIR"
    print_info "Thank you for using the Automated Network Scanner!"
}

main "$@"
