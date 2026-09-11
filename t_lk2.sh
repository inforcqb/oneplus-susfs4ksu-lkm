#!/system/bin/sh
# Pull the second panic dump and look for our step logs inside it.
exec > /data/local/tmp/lk2_out.txt 2>&1

SRC=/mnt/vendor/oplusreserve/media/log/minidump/SYSTEM_LAST_KMSG@1e50963a2401ee02500303e968ff628f@PJA110_11.H.11_3110_202601292238@2026_09_11_17_17_30.dat.gz

cp "$SRC" /data/local/tmp/lk2.gz
chmod 644 /data/local/tmp/lk2.gz
ls -l /data/local/tmp/lk2.gz

zcat /data/local/tmp/lk2.gz > /data/local/tmp/lk2.txt
echo "decompressed: $(wc -c < /data/local/tmp/lk2.txt) bytes"

echo "=== our module lines ==="
strings /data/local/tmp/lk2.txt | grep -a -e ih_hook -e ih_selftest | tail -30

echo "=== crash keywords ==="
strings /data/local/tmp/lk2.txt | grep -a -e "Unable to handle" -e "Internal error" -e "Kernel panic" -e "BUG:" -e "SError" | tail -20

echo "=== end ==="
