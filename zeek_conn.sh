#!/bin/sh
# Zeek CONN Log +JA4 Summarizer

LOGFILE="$1"

if [ -z "$LOGFILE" ] || [ ! -f "$LOGFILE" ]; then
    echo "Usage: $0 <path_to_conn.log>"
    exit 1
fi

echo "Analyzing $LOGFILE for connection metrics and JA4T fingerprints..."

if ! head -n 1 "$LOGFILE" | grep -q "^#"; then
    echo "Error: The file does not appear to be a standard Zeek TSV log."
    exit 1
fi

TMP_DATA=$(mktemp /tmp/zeek_conn_data.XXXXXX)
AWK_MAIN=$(mktemp /tmp/zeek_conn_main.XXXXXX)

# --- MAIN AWK PROCESSING SCRIPT ---
cat << 'EOF' > "$AWK_MAIN"
/^#fields/ {
    for(i=2; i<=NF; i++) {
        col[$i] = i - 1
    }
}
/^[^#]/ {
    orig_h     = $col["id.orig_h"]
    resp_h     = $col["id.resp_h"]
    resp_p     = $col["id.resp_p"]
    conn_state = $col["conn_state"]
    orig_b     = $col["orig_bytes"]
    resp_b     = $col["resp_bytes"]

    # Extract JA4T fields safely
    ja4t  = ("ja4t" in col) ? $col["ja4t"] : "-"
    ja4ts = ("ja4ts" in col) ? $col["ja4ts"] : "-"

    # Map Originators (Clients)
    if (orig_h != "-" && orig_h != "(empty)") {
        origs[orig_h]++
        if (resp_h != "-" && resp_h != "(empty)") {
            orig_resp[orig_h SUBSEP resp_h]++
        }
        if (orig_b != "-" && orig_b ~ /^[0-9]+$/) {
            orig_bytes[orig_h] += orig_b
        }
    }

    # Map Responders (Servers)
    if (resp_h != "-" && resp_h != "(empty)") {
        resps[resp_h]++
        if (resp_p != "-" && resp_p != "(empty)") {
            resp_port[resp_h SUBSEP resp_p]++
        }
    }

    # Map Destination Ports & Connection States
    if (resp_p != "-") ports[resp_p]++
    if (conn_state != "-") states[conn_state]++

    # Map JA4T (Client OS Fingerprint)
    if (ja4t != "-" && ja4t != "(empty)") {
        ja4t_count[ja4t]++
        ja4t_orig[ja4t SUBSEP orig_h]++
    }

    # Map JA4TS (Server OS Fingerprint)
    if (ja4ts != "-" && ja4ts != "(empty)") {
        ja4ts_count[ja4ts]++
        ja4ts_resp[ja4ts SUBSEP resp_h]++
    }
}
END {
    # Resolve top connections
    for (or_key in orig_resp) {
        split(or_key, arr, SUBSEP)
        o = arr[1]; r = arr[2]
        if (orig_resp[or_key] > orig_top_r_count[o]) {
            orig_top_r_count[o] = orig_resp[or_key]
            orig_top_r[o] = r
        }
    }

    for (rp_key in resp_port) {
        split(rp_key, arr, SUBSEP)
        r = arr[1]; p = arr[2]
        if (resp_port[rp_key] > resp_top_p_count[r]) {
            resp_top_p_count[r] = resp_port[rp_key]
            resp_top_p[r] = p
        }
    }

    # Resolve top IPs for JA4 hashes
    for (jo_key in ja4t_orig) {
        split(jo_key, arr, SUBSEP)
        j = arr[1]; o = arr[2]
        if (ja4t_orig[jo_key] > ja4t_top_orig_count[j]) {
            ja4t_top_orig_count[j] = ja4t_orig[jo_key]
            ja4t_top_orig[j] = o
        }
    }

    for (jr_key in ja4ts_resp) {
        split(jr_key, arr, SUBSEP)
        j = arr[1]; r = arr[2]
        if (ja4ts_resp[jr_key] > ja4ts_top_resp_count[j]) {
            ja4ts_top_resp_count[j] = ja4ts_resp[jr_key]
            ja4ts_top_resp[j] = r
        }
    }

    # Output formatting
    for (o in origs) {
        mb = orig_bytes[o] > 0 ? (orig_bytes[o] / 1048576) : 0
        printf "ORIG|%d|%s|%s|%.2f\n", origs[o], o, orig_top_r[o], mb
    }
    for (r in resps) printf "RESP|%d|%s|%s\n", resps[r], r, resp_top_p[r]
    for (p in ports) printf "PORT|%d|%s\n", ports[p], p
    for (s in states) printf "STATE|%d|%s\n", states[s], s

    for (o in orig_bytes) {
        mb = orig_bytes[o] / 1048576
        printf "BYTES|%d|%s|%.2f\n", orig_bytes[o], o, mb
    }

    for (jt in ja4t_count) printf "JA4T|%d|%s|%s\n", ja4t_count[jt], jt, ja4t_top_orig[jt]
    for (jts in ja4ts_count) printf "JA4TS|%d|%s|%s\n", ja4ts_count[jts], jts, ja4ts_top_resp[jts]
}
EOF

# --- EXECUTION ---
awk -F'\t' -f "$AWK_MAIN" "$LOGFILE" > "$TMP_DATA"

echo ""
echo "### TOP 10 BUSIEST ORIGINATORS (CLIENTS) ###"
echo "Count      Originator IP      Top Destination IP"
echo "----------------------------------------------------------------------"
grep "^ORIG|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 10 | awk -F'|' '{printf "%-10s %-18s %s\n", $2, $3, $4}'

echo ""
echo "### TOP 5 JA4T CLIENT OS FINGERPRINTS ###"
echo "Count      JA4T Hash                      Top Originator IP"
echo "----------------------------------------------------------------------"
grep "^JA4T|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 5 | awk -F'|' '{printf "%-10s %-30s %s\n", $2, $3, $4}'

echo ""
echo "### TOP 5 JA4TS SERVER OS FINGERPRINTS ###"
echo "Count      JA4TS Hash                     Top Responder IP"
echo "----------------------------------------------------------------------"
grep "^JA4TS|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 5 | awk -F'|' '{printf "%-10s %-30s %s\n", $2, $3, $4}'

echo ""
echo "### TOP 10 BUSIEST RESPONDERS (SERVERS) ###"
echo "Count      Responder IP       Most Hit Port on this Server"
echo "----------------------------------------------------------------------"
grep "^RESP|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 10 | awk -F'|' '{printf "%-10s %-18s %s\n", $2, $3, $4}'

echo ""
echo "### TOP 5 DATA EXPORTERS ###"
echo "Data Sent    Originator IP"
echo "--------------------------------------------------"
grep "^BYTES|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 5 | awk -F'|' '{printf "%-12s %s\n", $4 " MB", $3}'

echo ""
echo "### CONNECTION STATES SUMMARY ###"
echo "Count      State"
echo "--------------------------------------------------"
grep "^STATE|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | awk -F'|' '{printf "%-10s %s\n", $2, $3}'

# --- CLEANUP ---
rm -f "$TMP_DATA" "$AWK_MAIN"
