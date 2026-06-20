#!/bin/sh
# Zeek DNS Log Summarizer 
LOGFILE="$1"

if [ -z "$LOGFILE" ] || [ ! -f "$LOGFILE" ]; then
    echo "Usage: $0 <path_to_dns.log>"
    exit 1
fi

echo "Analyzing $LOGFILE for cross-referenced metrics..."

if ! head -n 1 "$LOGFILE" | grep -q "^#"; then
    echo "Error: The file does not appear to be a standard Zeek TSV log."
    exit 1
fi

# Use discrete temp files for the awk scripts and output data.
# This prevents the shell from parsing multi-line quotes and eliminates syntax errors.
TMP_DATA=$(mktemp /tmp/zeek_dns_data.XXXXXX)
AWK_MAIN=$(mktemp /tmp/zeek_awk_main.XXXXXX)
AWK_FMT=$(mktemp /tmp/zeek_awk_fmt.XXXXXX)

# --- MAIN AWK PROCESSING SCRIPT ---
cat << 'EOF' > "$AWK_MAIN"
/^#fields/ {
    for(i=2; i<=NF; i++) {
        col[$i] = i - 1
    }
}
/^[^#]/ {
    orig_h  = $col["id.orig_h"]
    resp_h  = $col["id.resp_h"]
    query   = $col["query"]
    qtype   = $col["qtype_name"]
    rcode   = $col["rcode_name"]

    # Safely handle the answers column if it is missing from the log
    answers = ("answers" in col) ? $col["answers"] : "-"

    if (orig_h != "-" && orig_h != "(empty)") {
        clients[orig_h]++
        if (query != "-" && query != "(empty)") {
            client_domain[orig_h SUBSEP query]++
            domain_client[query SUBSEP orig_h]++
        }
    }

    if (resp_h != "-" && resp_h != "(empty)") {
        servers[resp_h]++
    }

    if (query != "-" && query != "(empty)") {
        domains[query]++
        if (answers != "-" && answers != "(empty)") {
            domain_answers[query] = answers
        }
    }

    if (qtype != "-") qtypes[qtype]++
    if (rcode == "NXDOMAIN") nxdomains[query]++
}
END {
    for (cd in client_domain) {
        split(cd, arr, SUBSEP)
        c = arr[1]; d = arr[2]
        if (client_domain[cd] > client_top_d_count[c]) {
            client_top_d_count[c] = client_domain[cd]
            client_top_d[c] = d
        }
    }

    for (dc in domain_client) {
        split(dc, arr, SUBSEP)
        d = arr[1]; c = arr[2]
        if (domain_client[dc] > domain_top_c_count[d]) {
            domain_top_c_count[d] = domain_client[dc]
            domain_top_c[d] = c
        }
    }

    for (c in clients) printf "CLIENT|%d|%s|%s\n", clients[c], c, client_top_d[c]
    for (s in servers) printf "SERVER|%d|%s\n", servers[s], s
    for (d in domains) {
        ans = domain_answers[d] ? domain_answers[d] : "None/Unresolved"
        printf "DOMAIN|%d|%s|%s|%s\n", domains[d], d, domain_top_c[d], ans
    }
    for (nx in nxdomains) printf "NXDOMAIN|%d|%s\n", nxdomains[nx], nx
    for (qt in qtypes) printf "QTYPE|%d|%s\n", qtypes[qt], qt
}
EOF

# --- AWK FORMATTING SCRIPT FOR DOMAINS ---
cat << 'EOF' > "$AWK_FMT"
BEGIN { FS = "|" }
{
    dom = length($3) > 28 ? substr($3, 1, 25)"..." : $3;
    ans = length($5) > 25 ? substr($5, 1, 22)"..." : $5;
    printf "%-10s %-30s %-18s %s\n", $2, dom, $4, ans
}
EOF

# --- EXECUTION ---
# Run the main script against the log
awk -F'\t' -f "$AWK_MAIN" "$LOGFILE" > "$TMP_DATA"

echo ""
echo "### TOP 10 BUSIEST CLIENTS ###"
echo "Count      Client IP          Most Queried Domain by this Client"
echo "--------------------------------------------------------------------------------"
grep "^CLIENT|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 10 | awk -F'|' '{printf "%-10s %-18s %s\n", $2, $3, $4}'

echo ""
echo "### TOP 10 MOST QUERIED DOMAINS ###"
echo "Count      Domain                         Top Client IP      Resolved IPs (Answers)"
echo "--------------------------------------------------------------------------------"
grep "^DOMAIN|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 10 | awk -f "$AWK_FMT"

echo ""
echo "### TOP 5 BUSIEST DNS SERVERS ###"
echo "Count      Server IP"
echo "--------------------------------------------------"
grep "^SERVER|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 5 | awk -F'|' '{printf "%-10s %s\n", $2, $3}'

echo ""
echo "### TOP 10 NXDOMAIN QUERIES ###"
echo "Count      Failed Domain"
echo "--------------------------------------------------"
grep "^NXDOMAIN|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 10 | awk -F'|' '{printf "%-10s %s\n", $2, $3}'

echo ""
echo "### QUERY TYPES SUMMARY ###"
echo "Count      Type"
echo "--------------------------------------------------"
grep "^QTYPE|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 10 | awk -F'|' '{printf "%-10s %s\n", $2, $3}'

# --- CLEANUP ---
rm -f "$TMP_DATA" "$AWK_MAIN" "$AWK_FMT"
