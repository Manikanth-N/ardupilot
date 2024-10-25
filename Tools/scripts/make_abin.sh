#!/bin/sh
# make an abin file for a firmware this file format is for sending to
# a memory constrained companion computer to flash over serial to a
# flight board

if [ $# -lt 2 ]; then
    echo "Usage: make_abin.sh BINFILE ABINFILE"
    exit 1
fi

BINFILE="$1"
ABINFILE="$2"

[ -f "$BINFILE" ] || {
    echo "Can't find bin file $BINFILE for abin"
    exit 1
}

# sum=$(md5sum "$BINFILE" | cut -d' ' -f1)
sum=$(sha256sum "$BINFILE" | cut -d' ' -f1)

# Get the current Git commit hash and generate its SHA-256 hash
githash=$(git rev-parse HEAD | sha256sum | awk '{print $1}')

# echo "githash $githash md5 $sum"
echo "githash $githash sha256 $sum"

cat <<EOF > "$ABINFILE"
git version: $githash
SHA256: $sum
--
EOF
cat "$BINFILE" >> "$ABINFILE"

echo "Created $ABINFILE"

