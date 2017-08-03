#!/bin/bash

TESTDATA_PATH="testdata/"
DOMAINS="chrissnijder.nl vurehout.net wikipedia.org"

echo "[+] Purging testdata dir.."
rm -rfvd "$TESTDATA_PATH"

echo "[+] Creating new testdata dir.."
mkdir -p "$TESTDATA_PATH"

for DOMAIN in $DOMAINS; do
    echo "[+] Creating dir for $DOMAIN.."
    mkdir -p "$TESTDATA_PATH$DOMAIN"
    echo "[+] Fetching cert for $DOMAIN"
    echo "" | \
    openssl s_client -connect $DOMAIN:443 \
        -servername chrissnijder.nl \
        -showcerts 2>&1  | \
    sed  -n "/-----BEGIN/,/-----END/ w $TESTDATA_PATH$DOMAIN/chain.pem"
done
echo "[+] Start ocspd with the desired verbosity and test directory e.g.:"
echo "python ocspd -vvvv -d testdata/*"
