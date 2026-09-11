#!/system/bin/sh
# Pull the newest panic dump and find exactly where it died.
exec > /data/local/tmp/lk4_out.txt 2>&1

DIR=/mnt/vendor/oplusreserve/media/log/minidump
F=$(ls -t $DIR/SYSTEM_LAST_KMSG* 2>/dev/null | head -1)
echo "newest dump: $F"

cp "$F" /data/local/tmp/lk4.gz
chmod 644 /data/local/tmp/lk4.gz
zcat /data/local/tmp/lk4.gz > /data/local/tmp/lk4.txt
echo "size: $(wc -c < /data/local/tmp/lk4.txt)"

echo "=== our module lines ==="
strings /data/local/tmp/lk4.txt | grep -a -e ih_hook -e ih_selftest | tail -20

echo "=== panic / fault ==="
strings /data/local/tmp/lk4.txt | grep -a -e "Kernel panic" -e "BTI" -e "Unable to handle" -e "Internal error" -e "Oops" -e "pc :" -e "lr :" -e "init_module" | tail -30

echo "=== end ==="
