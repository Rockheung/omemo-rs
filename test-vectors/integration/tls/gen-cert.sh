#!/usr/bin/env bash
# Generate a self-signed TLS cert for the omemo-rs E2E rig.
#
# nginx (Converse.js page) and Prosody (BOSH/WS port 5281) both
# need a cert that the browser will accept for *every* hostname
# the operator might use to reach the stack — `localhost`, the
# loopback IP, and any LAN IPs returned by `hostname -I`. The
# script bakes those into the cert's `subjectAltName` so a single
# cert works from a phone (LAN IP), a laptop on the same Wi-Fi,
# and the host machine itself.
#
# Output: `cert.pem` + `key.pem` next to this script. Both are
# gitignored. Re-run after a network change (new LAN IP, new
# hostname) — Prosody and nginx pick up the new files on next
# `docker compose up -d --force-recreate`.
#
# Browsers will still warn on first visit (the cert has no chain
# back to a public CA). Accept the warning once per origin. See
# `docs/converse-e2e.md` for the workflow.

set -euo pipefail
cd "$(dirname "$0")"

SAN_HOSTS=("localhost" "*.localhost" "omemo-rs-prosody" "omemo-rs-converse")
SAN_IPS=("127.0.0.1" "::1")

# Pick up every interface address `hostname -I` knows about. Skips
# docker-internal bridge IPs by default — they're routable from
# host but not particularly useful (containers reach each other by
# service name on the compose network).
if command -v hostname >/dev/null 2>&1; then
    for ip in $(hostname -I 2>/dev/null || true); do
        case "$ip" in
            172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) ;;  # docker bridges
            *) SAN_IPS+=("$ip") ;;
        esac
    done
    # Also include every hostname / alias the box answers to.
    # Operators often access the rig at https://<machine-name>:8766/
    # rather than via a numeric IP. `hostname -A` returns the full
    # alias list (FQDN + short + mDNS-style names like `host.lcl`);
    # `hostname` alone gives the short form when the FQDN is set
    # via /etc/hosts rather than DNS.
    for h in $(hostname 2>/dev/null) \
             $(hostname -f 2>/dev/null) \
             $(hostname -s 2>/dev/null) \
             $(hostname -A 2>/dev/null); do
        # Drop empties + duplicates of `localhost`.
        [ -n "$h" ] && [ "$h" != "localhost" ] && SAN_HOSTS+=("$h")
    done
fi
# De-dup SAN_HOSTS preserving order.
declare -A seen=()
unique_hosts=()
for h in "${SAN_HOSTS[@]}"; do
    if [ -z "${seen[$h]:-}" ]; then
        unique_hosts+=("$h")
        seen[$h]=1
    fi
done
SAN_HOSTS=("${unique_hosts[@]}")

# Build the SAN extension line.
san=""
for h in "${SAN_HOSTS[@]}"; do san+="DNS:$h,"; done
for i in "${SAN_IPS[@]}";  do san+="IP:$i,";  done
san="${san%,}"

echo "Generating cert with SAN: $san"

openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout key.pem -out cert.pem \
    -days 3650 \
    -subj "/CN=omemo-rs-e2e/O=omemo-rs/OU=integration-fixture" \
    -addext "subjectAltName=$san" \
    -addext "extendedKeyUsage=serverAuth" \
    2>&1 | sed '/^writing/d'

chmod 0644 cert.pem
chmod 0644 key.pem
echo "Wrote: $(realpath cert.pem) and $(realpath key.pem)"
echo "Mount path inside nginx:   /etc/nginx/tls/{cert,key}.pem"
echo "Mount path inside ejabberd: /opt/ejabberd/conf/{cert,key}.pem"
echo
echo "ejabberd accepts SNI for any hostname covered by the cert"
echo "SAN out of the box — no sidecar config needed."
