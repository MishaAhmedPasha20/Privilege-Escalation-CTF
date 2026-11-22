#!/bin/bash
# Run as root. Generates one random flag per misconfig.

> flags.hash

for id in 1 2 3 4; do
    flag="FLAG{$(openssl rand -hex 8)}"
    hash=$(printf '%s' "$flag" | sha256sum | awk '{print $1}')
    echo "$id:$hash" >> flags.hash
    echo "$flag" > /root/flag$id.txt
    chmod 600 /root/flag$id.txt
    chown root:root /root/flag$id.txt
    echo "Flag $id placed at /root/flag$id.txt"
done

chmod 644 flags.hash
echo "Hashes written to flags.hash"
