#!/bin/sh
#Zeek SSL/JA4 Log Summarizer

LOGFILE="$1"

if [ -z "$LOGFILE" ] || [ ! -f "$LOGFILE" ]; then
    echo "Usage: $0 <path_to_ssl.log>"
    exit 1
fi

echo "Analyzing $LOGFILE for TLS and JA4 fingerprints..."

if ! head -n 1 "$LOGFILE" | grep -q "^#"; then
    echo "Error: The file does not appear to be a standard Zeek TSV log."
    exit 1
fi

TMP_DATA=$(mktemp /tmp/zeek_ssl_data.XXXXXX)
AWK_MAIN=$(mktemp /tmp/zeek_ssl_main.XXXXXX)

# --- MAIN AWK PROCESSING SCRIPT ---
cat << 'EOF' > "$AWK_MAIN"
/^#fields/ {
    for(i=2; i<=NF; i++) {
        col[$i] = i - 1
    }
}
/^[^#]/ {
    orig_h = $col["id.orig_h"]
    resp_h = $col["id.resp_h"]
    sni    = $col["server_name"]
    ver    = $col["version"]
    ciph   = $col["cipher"]

    # Safely handle JA4 fields in case they are missing in older logs
    ja4  = ("ja4" in col) ? $col["ja4"] : "-"
    ja4s = ("ja4s" in col) ? $col["ja4s"] : "-"

    # Track Server Names (SNI)
    if (sni != "-" && sni != "(empty)") {
        snis[sni]++
        sni_orig[sni SUBSEP orig_h]++
    }

    # Track TLS Versions and Ciphers
    if (ver != "-" && ver != "(empty)") vers[ver]++
    if (ciph != "-" && ciph != "(empty)") ciphs[ciph]++

    # Track JA4 Client Fingerprints
    if (ja4 != "-" && ja4 != "(empty)") {
        ja4_count[ja4]++
        ja4_orig[ja4 SUBSEP orig_h]++
        ja4_sni[ja4 SUBSEP sni]++
    }

    # Track JA4S Server Fingerprints
    if (ja4s != "-" && ja4s != "(empty)") ja4s_count[ja4s]++
}
END {
    # Find the top client IP and SNI for each JA4 fingerprint
    for (j_orig in ja4_orig) {
        split(j_orig, arr, SUBSEP)
        j = arr[1]; o = arr[2]
        if (ja4_orig[j_orig] > ja4_top_orig_count[j]) {
            ja4_top_orig_count[j] = ja4_orig[j_orig]
            ja4_top_orig[j] = o
        }
    }
    for (j_sni in ja4_sni) {
        split(j_sni, arr, SUBSEP)
        j = arr[1]; s = arr[2]
        if (ja4_sni[j_sni] > ja4_top_sni_count[j]) {
            ja4_top_sni_count[j] = ja4_sni[j_sni]
            ja4_top_sni[j] = s
        }
    }

    # Find the top client IP for each SNI
    for (s_orig in sni_orig) {
        split(s_orig, arr, SUBSEP)
        s = arr[1]; o = arr[2]
        if (sni_orig[s_orig] > sni_top_orig_count[s]) {
            sni_top_orig_count[s] = sni_orig[s_orig]
            sni_top_orig[s] = o
        }
    }

    # Output formatted records
    for (s in snis) printf "SNI|%d|%s|%s\n", snis[s], s, sni_top_orig[s]
    for (j in ja4_count) printf "JA4|%d|%s|%s|%s\n", ja4_count[j], j, ja4_top_orig[j], ja4_top_sni[j]
    for (js in ja4s_count) printf "JA4S|%d|%s\n", ja4s_count[js], js
    for (v in vers) printf "VER|%d|%s\n", vers[v], v
    for (c in ciphs) printf "CIPH|%d|%s\n", ciphs[c], c
}
EOF

# --- EXECUTION ---
awk -F'\t' -f "$AWK_MAIN" "$LOGFILE" > "$TMP_DATA"

echo ""
echo "### TOP 10 SERVER NAMES (SNI) ###"
echo "Count      SNI Domain                     Top Originator IP"
echo "----------------------------------------------------------------------"
grep "^SNI|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 10 | awk -F'|' '{
    sni = length($3) > 30 ? substr($3, 1, 27)"..." : $3;
    printf "%-10s %-30s %s\n", $2, sni, $4
}'

echo ""
echo "### TOP 10 JA4 CLIENT FINGERPRINTS ###"
echo "Count      JA4 Hash                             Top Originator IP  Most Associated SNI"
echo "----------------------------------------------------------------------------------------------------"
grep "^JA4|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 10 | awk -F'|' '{
    sni = length($5) > 25 ? substr($5, 1, 22)"..." : $5;
    printf "%-10s %-36s %-18s %s\n", $2, $3, $4, sni
}'

echo ""
echo "### TOP 5 JA4S SERVER FINGERPRINTS ###"
echo "Count      JA4S Hash"
echo "--------------------------------------------------"
grep "^JA4S|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 5 | awk -F'|' '{printf "%-10s %s\n", $2, $3}'

echo ""
echo "### TLS VERSIONS ###"
echo "Count      Version"
echo "--------------------------------------------------"
grep "^VER|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | awk -F'|' '{printf "%-10s %s\n", $2, $3}'

echo ""
echo "### TOP 10 CIPHERS ###"
echo "Count      Cipher Suite"
echo "--------------------------------------------------"
grep "^CIPH|" "$TMP_DATA" | sort -t '|' -k 2 -r -n | head -n 10 | awk -F'|' '{printf "%-10s %s\n", $2, $3}'

# --- CLEANUP ---
rm -f "$TMP_DATA" "$AWK_MAIN"
